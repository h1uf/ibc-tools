package chain

import (
	"cosmossdk.io/log"
	"crypto/sha256"
	"fmt"
	"github.com/cometbft/cometbft/libs/rand"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	types2 "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/proto/tendermint/version"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/testutil/mock"
	"github.com/cosmos/iavl"
	dbm "github.com/cosmos/iavl/db"
	"github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	ibctm "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	ics23 "github.com/cosmos/ics23/go"
	"time"
)

var upgradePath = []string{"upgrade", "upgradedIBCState"}

// these specs I'm sending to the chain when creating a client
// iavl because I'm using it(it's simpler that writing my own root hash oin the hash but in reality it doesn't have to be any merkle tree)
var spec = []*ics23.ProofSpec{ics23.IavlSpec,
	{
		// spec for the parent tendermint tree is just hashing of key + value. We don't have any leafs/inner nodes here. Just one key and one value.
		LeafSpec: &ics23.LeafOp{
			PrehashKey:   ics23.HashOp_NO_HASH,
			Hash:         ics23.HashOp_SHA256,
			PrehashValue: ics23.HashOp_NO_HASH,
		},
		InnerSpec: &ics23.InnerSpec{
			Hash: ics23.HashOp_SHA256,
		},
	}}

type LocalChain struct {
	prefix           []byte
	tree             *iavl.MutableTree
	vals             *tmtypes.ValidatorSet
	signersByAddress map[string]tmtypes.PrivValidator
	spec             []*ics23.ProofSpec
	version          version.Consensus
	lastBlock        tmtypes.BlockID
	chainId          string
	height           int64
	round            int32
	revision         int64
	trustedHeight    int64
	lastHash         []byte
}

func NewLocalChain(prefix []byte, validatorsCount int, chainId string, revision int64) *LocalChain {
	// here we just init some sort of chain simulation so it could produce headers to advance add root
	signersByAddress := make(map[string]tmtypes.PrivValidator, validatorsCount)
	validators := make([]*tmtypes.Validator, 0)

	for i := 0; i < validatorsCount; i++ {
		privVal := mock.NewPV()
		pubKey, _ := privVal.GetPubKey()
		validators = append(validators, tmtypes.NewValidator(pubKey, 1))
		signersByAddress[pubKey.Address().String()] = privVal
	}
	valSet := tmtypes.NewValidatorSet(validators)
	var tree = iavl.NewMutableTree(dbm.NewMemDB(), 0, true, log.NewNopLogger())
	randomBytes := rand.Bytes(32)
	_, _ = tree.Set(randomBytes, randomBytes)
	return &LocalChain{tree: tree,
		prefix:           prefix,
		vals:             valSet,
		signersByAddress: signersByAddress,
		spec:             spec,
		version:          version.Consensus{App: 0, Block: 11},
		chainId:          chainId,
		trustedHeight:    1,
		height:           2,
		round:            1,
		revision:         revision}

}
func (a *LocalChain) GetClientState() *ibctm.ClientState {

	return &ibctm.ClientState{
		ChainId:         a.chainId,
		TrustLevel:      ibctm.DefaultTrustLevel,
		TrustingPeriod:  time.Hour * 2,
		UnbondingPeriod: time.Hour * 3,
		MaxClockDrift:   time.Hour,
		LatestHeight:    types.Height{RevisionNumber: uint64(a.revision), RevisionHeight: uint64(a.trustedHeight)},
		ProofSpecs:      a.spec,
		UpgradePath:     upgradePath,
	}
}

func (a *LocalChain) GetConsensusState() *ibctm.ConsensusState {

	if a.lastHash == nil {
		a.lastHash = a.getAppHash()
	}

	ts := time.Now()
	return &ibctm.ConsensusState{
		Timestamp:          ts,
		Root:               commitmenttypes.NewMerkleRoot(a.lastHash),
		NextValidatorsHash: a.vals.Hash(),
	}
}

// this one just advances the chain and returns the ehader that we can send to the real chain
func (a *LocalChain) Advance() *ibctm.Header {

	appHash := a.getAppHash()
	a.lastHash = appHash
	psHeader := tmtypes.PartSetHeader{Total: 2, Hash: a.doHash([]byte("ps_header"))}
	header := tmtypes.Header{
		ValidatorsHash:     a.vals.Hash(),
		Version:            a.version,
		Time:               time.Now(),
		LastBlockID:        a.lastBlock,
		ChainID:            a.chainId,
		Height:             a.height,
		LastCommitHash:     a.doHash([]byte("last_commit")),
		DataHash:           a.doHash([]byte("data_hash")),
		NextValidatorsHash: a.vals.Hash(),
		ConsensusHash:      a.doHash([]byte("consensus_hash")),
		AppHash:            appHash,
		LastResultsHash:    a.doHash([]byte("last_res_hash")),
		EvidenceHash:       a.doHash([]byte("evidence_hash")),
		ProposerAddress:    a.vals.Proposer.Address,
	}
	headerHash := header.Hash()
	blockId := tmtypes.BlockID{PartSetHeader: psHeader, Hash: headerHash}
	a.lastBlock = blockId
	commit := tmtypes.Commit{Height: header.Height, Round: a.round, BlockID: blockId}

	signatures := make([]tmtypes.CommitSig, 0)
	for i, val := range a.vals.Validators {

		vote := cmtproto.Vote{
			Type:   cmtproto.PrecommitType,
			Height: commit.Height,
			Round:  commit.Round,
			BlockID: cmtproto.BlockID{Hash: blockId.Hash,
				PartSetHeader: cmtproto.PartSetHeader{Total: blockId.PartSetHeader.Total, Hash: blockId.PartSetHeader.Hash}},
			Timestamp:        header.Time,
			ValidatorAddress: val.Address,
			ValidatorIndex:   int32(i),
		}
		signer := a.signersByAddress[val.Address.String()]
		_ = signer.SignVote(a.chainId, &vote)
		sig := tmtypes.CommitSig{
			BlockIDFlag:      tmtypes.BlockIDFlagCommit,
			ValidatorAddress: val.Address,
			Timestamp:        header.Time,
			Signature:        vote.Signature,
		}
		signatures = append(signatures, sig)
	}
	commit.Signatures = signatures
	signedHeader := types2.SignedHeader{Commit: commit.ToProto(), Header: header.ToProto()}

	protoVals, _ := a.vals.ToProto()
	trHeight := types.Height{RevisionNumber: uint64(a.revision), RevisionHeight: uint64(a.trustedHeight)}
	res := &ibctm.Header{
		SignedHeader:      &signedHeader,
		ValidatorSet:      protoVals,
		TrustedHeight:     trHeight,
		TrustedValidators: protoVals,
	}
	a.height++
	if a.height%10 == 0 {
		a.round++
	}

	a.trustedHeight++
	return res

}

// height of the last header

func (a *LocalChain) Height() types.Height {
	return types.Height{RevisionNumber: uint64(a.revision), RevisionHeight: uint64(a.height - 1)}
}

// sets the key
func (a *LocalChain) Set(key, val []byte) {
	_, _ = a.tree.Set(key, val)
	_, _, err := a.tree.SaveVersion()
	if err != nil {
		panic(err)
	}
}

// computes "merkle" root
func (a *LocalChain) getAppHash() []byte {
	treeRoot, _, _ := a.tree.SaveVersion()
	data := make([]byte, 0)
	data = append(data, a.prefix...)
	data = append(data, treeRoot...)

	return a.doHash(data)
}

func (a *LocalChain) GetMembershipProof(key []byte) commitmenttypes.MerkleProof {
	mainProof, err := a.tree.GetMembershipProof(key)
	if err != nil {
		fmt.Println(err)
	}
	// since we have no parent tendermint tree we have to pretend that we do
	// so according to the spec verification will do hash(key + val) where key is the prefix and val is the merkle root of the child tree
	onTop := &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Exist{
			Exist: &ics23.ExistenceProof{
				Key:   a.prefix,
				Value: a.tree.Hash(),
				Leaf: &ics23.LeafOp{PrehashKey: ics23.HashOp_NO_HASH,
					Hash:         ics23.HashOp_SHA256,
					PrehashValue: ics23.HashOp_NO_HASH},
				Path: []*ics23.InnerOp{},
			},
		},
	}

	return commitmenttypes.MerkleProof{Proofs: []*ics23.CommitmentProof{mainProof, onTop}}

}
func (a *LocalChain) doHash(preimage []byte) []byte {
	hh := sha256.New()
	hh.Write(preimage)

	return hh.Sum(nil)
}
