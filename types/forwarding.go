package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cosmos/gogoproto/proto"
)

func (h Hop) String() string {
	return fmt.Sprintf("%s/%s", h.PortId, h.ChannelId)
}

func (ftpd FungibleTokenPacketDataV2) GetBytes() []byte {
	bz, err := proto.Marshal(&ftpd)
	if err != nil {
		panic(errors.New("cannot marshal FungibleTokenPacketDataV2 into bytes"))
	}

	return bz
}

func (ftpd FungibleTokenPacketData) GetBytes() []byte {
	bz, err := json.Marshal(ftpd)
	if err != nil {
		panic(errors.New("cannot marshal FungibleTokenPacketData into bytes"))
	}

	return bz
}
