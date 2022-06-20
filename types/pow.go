package types

import (
	"bytes"
	//	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/internal/jsontypes"
	tmmath "github.com/tendermint/tendermint/libs/math"
	//	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// Work represents any provable malicious activity by a validator.
// Verification logic for each work is part of the work module.
type Work interface {
	ABCI() []abci.Misbehavior // forms individual work to be sent to the application
	Bytes() []byte            // bytes which comprise the work
	Hash() []byte             // hash of the work
	Height() int64            // height of the infraction
	String() string           // string format of the work
	Time() time.Time          // time of the infraction
	ValidateBasic() error     // basic consistency check

	// Implementations must support tagged encoding in JSON.
	jsontypes.Tagged
}

//--------------------------------------------------------------------------------------

// FloatWork contains work of a single validator signing two conflicting votes.
type FloatWork struct {
	// abci specific information
	TotalVotingPower int64 `json:",string"`
	ValidatorPower   int64 `json:",string"`
	Timestamp        time.Time
}

// TypeTag implements the jsontypes.Tagged interface.
func (*FloatWork) TypeTag() string { return "tendermint/FloatWork" }

var _ Work = &FloatWork{}

// NewFloatWork creates FloatWork with right ordering given
func NewFloatWork(blockTime time.Time, valSet *ValidatorSet) (*FloatWork, error) {
	return &FloatWork{
		TotalVotingPower: valSet.TotalVotingPower(),
		ValidatorPower:   val.VotingPower,
		Timestamp:        blockTime,
	}, nil
}

// ABCI returns the application relevant representation of the work
func (dve *FloatWork) ABCI() []abci.Misbehavior {
	return []abci.Misbehavior{{
		Type: abci.MisbehaviorType_DUPLICATE_VOTE,
		Validator: abci.Validator{
			Address: dve.VoteA.ValidatorAddress,
			Power:   dve.ValidatorPower,
		},
		Height:           dve.VoteA.Height,
		Time:             dve.Timestamp,
		TotalVotingPower: dve.TotalVotingPower,
	}}
}

// Bytes returns the proto-encoded work as a byte array.
func (dve *FloatWork) Bytes() []byte {
	pbe := dve.ToProto()
	bz, err := pbe.Marshal()
	if err != nil {
		panic("marshaling duplicate vote work to bytes: " + err.Error())
	}

	return bz
}

// Hash returns the hash of the work.
func (dve *FloatWork) Hash() []byte {
	return crypto.Checksum(dve.Bytes())
}

// Height returns the height of the infraction
func (dve *FloatWork) Height() int64 {
	return dve.VoteA.Height
}

// String returns a string representation of the work.
func (dve *FloatWork) String() string {
	return fmt.Sprintf("FloatWork{VoteA: %v, VoteB: %v}", dve.VoteA, dve.VoteB)
}

// Time returns the time of the infraction
func (dve *FloatWork) Time() time.Time {
	return dve.Timestamp
}

// ValidateBasic performs basic validation.
func (dve *FloatWork) ValidateBasic() error {
	if dve == nil {
		return errors.New("empty duplicate vote work")
	}

	if dve.VoteA == nil || dve.VoteB == nil {
		return fmt.Errorf("one or both of the votes are empty %v, %v", dve.VoteA, dve.VoteB)
	}
	if err := dve.VoteA.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid VoteA: %w", err)
	}
	if err := dve.VoteB.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid VoteB: %w", err)
	}
	// Enforce Votes are lexicographically sorted on blockID
	if strings.Compare(dve.VoteA.BlockID.Key(), dve.VoteB.BlockID.Key()) >= 0 {
		return errors.New("duplicate votes in invalid order")
	}
	return nil
}

// ValidateABCI validates the ABCI component of the work by checking the
// timestamp, validator power and total voting power.
func (dve *FloatWork) ValidateABCI(
	val *Validator,
	valSet *ValidatorSet,
	workTime time.Time,
) error {

	if dve.Timestamp != workTime {
		return fmt.Errorf(
			"work has a different time to the block it is associated with (%v != %v)",
			dve.Timestamp, workTime)
	}

	if val.VotingPower != dve.ValidatorPower {
		return fmt.Errorf("validator power from work and our validator set does not match (%d != %d)",
			dve.ValidatorPower, val.VotingPower)
	}
	if valSet.TotalVotingPower() != dve.TotalVotingPower {
		return fmt.Errorf("total voting power from the work and our validator set does not match (%d != %d)",
			dve.TotalVotingPower, valSet.TotalVotingPower())
	}

	return nil
}

// GenerateABCI populates the ABCI component of the work. This includes the
// validator power, timestamp and total voting power.
func (dve *FloatWork) GenerateABCI(
	val *Validator,
	valSet *ValidatorSet,
	workTime time.Time,
) {
	dve.ValidatorPower = val.VotingPower
	dve.TotalVotingPower = valSet.TotalVotingPower()
	dve.Timestamp = workTime
}

// ToProto encodes FloatWork to protobuf
func (dve *FloatWork) ToProto() *tmproto.FloatWork {
	voteB := dve.VoteB.ToProto()
	voteA := dve.VoteA.ToProto()
	tp := tmproto.FloatWork{
		VoteA:            voteA,
		VoteB:            voteB,
		TotalVotingPower: dve.TotalVotingPower,
		ValidatorPower:   dve.ValidatorPower,
		Timestamp:        dve.Timestamp,
	}
	return &tp
}

// FloatWorkFromProto decodes protobuf into FloatWork
func FloatWorkFromProto(pb *tmproto.FloatWork) (*FloatWork, error) {
	if pb == nil {
		return nil, errors.New("nil duplicate vote work")
	}

	var vA *Vote
	if pb.VoteA != nil {
		var err error
		vA, err = VoteFromProto(pb.VoteA)
		if err != nil {
			return nil, err
		}
		if err = vA.ValidateBasic(); err != nil {
			return nil, err
		}
	}

	var vB *Vote
	if pb.VoteB != nil {
		var err error
		vB, err = VoteFromProto(pb.VoteB)
		if err != nil {
			return nil, err
		}
		if err = vB.ValidateBasic(); err != nil {
			return nil, err
		}
	}

	dve := &FloatWork{
		VoteA:            vA,
		VoteB:            vB,
		TotalVotingPower: pb.TotalVotingPower,
		ValidatorPower:   pb.ValidatorPower,
		Timestamp:        pb.Timestamp,
	}

	return dve, dve.ValidateBasic()
}


//------------------------------------------------------------------------------------------

// WorkList is a list of Work. Works is not a word.
type WorkList []Work

// StringIndented returns a string representation of the work.
func (wl WorkList) StringIndented(indent string) string {
	if wl == nil {
		return "nil-Work"
	}
	evStrings := make([]string, tmmath.MinInt(len(wl), 21))
	for i, ev := range wl {
		if i == 20 {
			evStrings[i] = fmt.Sprintf("... (%v total)", len(wl))
			break
		}
		evStrings[i] = fmt.Sprintf("Work:%v", ev)
	}
	return fmt.Sprintf(`WorkList{
%s  %v
%s}#%v`,
		indent, strings.Join(evStrings, "\n"+indent+"  "),
		indent, wl.Hash())
}

// ByteSize returns the total byte size of all the work
func (wl WorkList) ByteSize() int64 {
	if len(wl) != 0 {
		pb, err := wl.ToProto()
		if err != nil {
			panic(err)
		}
		return int64(pb.Size())
	}
	return 0
}

// FromProto sets a protobuf WorkList to the given pointer.
func (wl *WorkList) FromProto(eviList *tmproto.WorkList) error {
	if eviList == nil {
		return errors.New("nil work list")
	}

	eviBzs := make(WorkList, len(eviList.Work))
	for i := range eviList.Work {
		evi, err := WorkFromProto(&eviList.Work[i])
		if err != nil {
			return err
		}
		eviBzs[i] = evi
	}
	*wl = eviBzs
	return nil
}

// ToProto converts WorkList to protobuf
func (wl *WorkList) ToProto() (*tmproto.WorkList, error) {
	if wl == nil {
		return nil, errors.New("nil work list")
	}

	eviBzs := make([]tmproto.Work, len(*wl))
	for i, v := range *wl {
		protoEvi, err := WorkToProto(v)
		if err != nil {
			return nil, err
		}
		eviBzs[i] = *protoEvi
	}
	return &tmproto.WorkList{Work: eviBzs}, nil
}

func (wl WorkList) MarshalJSON() ([]byte, error) {
	lst := make([]json.RawMessage, len(wl))
	for i, ev := range wl {
		bits, err := jsontypes.Marshal(ev)
		if err != nil {
			return nil, err
		}
		lst[i] = bits
	}
	return json.Marshal(lst)
}

func (wl *WorkList) UnmarshalJSON(data []byte) error {
	var lst []json.RawMessage
	if err := json.Unmarshal(data, &lst); err != nil {
		return err
	}
	out := make([]Work, len(lst))
	for i, elt := range lst {
		if err := jsontypes.Unmarshal(elt, &out[i]); err != nil {
			return err
		}
	}
	*wl = WorkList(out)
	return nil
}

// Hash returns the simple merkle root hash of the WorkList.
func (wl WorkList) Hash() []byte {
	// These allocations are required because Work is not of type Bytes, and
	// golang slices can't be typed cast. This shouldn't be a performance problem since
	// the Work size is capped.
	workBzs := make([][]byte, len(wl))
	for i := 0; i < len(wl); i++ {
		// TODO: We should change this to the hash. Using bytes contains some unexported data that
		// may cause different hashes
		workBzs[i] = wl[i].Bytes()
	}
	return merkle.HashFromByteSlices(workBzs)
}

func (wl WorkList) String() string {
	s := ""
	for _, e := range wl {
		s += fmt.Sprintf("%s\t\t", e)
	}
	return s
}

// Has returns true if the work is in the WorkList.
func (wl WorkList) Has(work Work) bool {
	for _, ev := range wl {
		if bytes.Equal(work.Hash(), ev.Hash()) {
			return true
		}
	}
	return false
}

// ToABCI converts the work list to a slice of the ABCI protobuf messages
// for use when communicating the work to an application.
func (wl WorkList) ToABCI() []abci.Misbehavior {
	var el []abci.Misbehavior
	for _, e := range wl {
		el = append(el, e.ABCI()...)
	}
	return el
}

//------------------------------------------ PROTO --------------------------------------

// WorkToProto is a generalized function for encoding work that conforms to the
// work interface to protobuf
func WorkToProto(work Work) (*tmproto.Work, error) {
	if work == nil {
		return nil, errors.New("nil work")
	}

	switch evi := work.(type) {
	case *FloatWork:
		pbev := evi.ToProto()
		return &tmproto.Work{
			Sum: &tmproto.Work_FloatWork{
				FloatWork: pbev,
			},
		}, nil

	case *LightClientAttackWork:
		pbev, err := evi.ToProto()
		if err != nil {
			return nil, err
		}
		return &tmproto.Work{
			Sum: &tmproto.Work_LightClientAttackWork{
				LightClientAttackWork: pbev,
			},
		}, nil

	default:
		return nil, fmt.Errorf("toproto: work is not recognized: %T", evi)
	}
}

// WorkFromProto is a generalized function for decoding protobuf into the
// work interface
func WorkFromProto(work *tmproto.Work) (Work, error) {
	if work == nil {
		return nil, errors.New("nil work")
	}

	switch evi := work.Sum.(type) {
	case *tmproto.Work_FloatWork:
		return FloatWorkFromProto(evi.FloatWork)
	case *tmproto.Work_LightClientAttackWork:
		return LightClientAttackWorkFromProto(evi.LightClientAttackWork)
	default:
		return nil, errors.New("work is not recognized")
	}
}

func init() {
	jsontypes.MustRegister((*FloatWork)(nil))
	jsontypes.MustRegister((*LightClientAttackWork)(nil))
}

//-------------------------------------------- ERRORS --------------------------------------

// ErrInvalidWork wraps a piece of work and the error denoting how or why it is invalid.
type ErrInvalidWork struct {
	Work   Work
	Reason error
}

// NewErrInvalidWork returns a new WorkInvalid with the given err.
func NewErrInvalidWork(ev Work, err error) *ErrInvalidWork {
	return &ErrInvalidWork{ev, err}
}

// Error returns a string representation of the error.
func (err *ErrInvalidWork) Error() string {
	return fmt.Sprintf("Invalid work: %v. Work: %v", err.Reason, err.Work)
}

// ErrWorkOverflow is for when there the amount of work exceeds the max bytes.
type ErrWorkOverflow struct {
	Max int64
	Got int64
}

// NewErrWorkOverflow returns a new ErrWorkOverflow where got > max.
func NewErrWorkOverflow(max, got int64) *ErrWorkOverflow {
	return &ErrWorkOverflow{max, got}
}

// Error returns a string representation of the error.
func (err *ErrWorkOverflow) Error() string {
	return fmt.Sprintf("Too much work: Max %d, got %d", err.Max, err.Got)
}

//-------------------------------------------- MOCKING --------------------------------------

// unstable - use only for testing

// assumes the round to be 0 and the validator index to be 0
// func NewMockFloatWork(ctx context.Context, height int64, time time.Time, chainID string) (*FloatWork, error) {
// 	val := NewMockPV()
// 	return NewMockFloatWorkWithValidator(ctx, height, time, val, chainID)
// }
//
// // assumes voting power to be 10 and validator to be the only one in the set
// func NewMockFloatWorkWithValidator(ctx context.Context, height int64, time time.Time, pv PrivValidator, chainID string) (*FloatWork, error) {
// 	pubKey, err := pv.GetPubKey(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	val := NewValidator(pubKey, 10)
// 	voteA := makeMockVote(height, 0, 0, pubKey.Address(), randBlockID(), time)
// 	vA := voteA.ToProto()
// 	_ = pv.SignVote(ctx, chainID, vA)
// 	voteA.Signature = vA.Signature
// 	voteB := makeMockVote(height, 0, 0, pubKey.Address(), randBlockID(), time)
// 	vB := voteB.ToProto()
// 	_ = pv.SignVote(ctx, chainID, vB)
// 	voteB.Signature = vB.Signature
// 	ev, err := NewFloatWork(voteA, voteB, time, NewValidatorSet([]*Validator{val}))
// 	if err != nil {
// 		return nil, fmt.Errorf("constructing mock duplicate vote work: %w", err)
// 	}
// 	return ev, nil
// }
//
// func makeMockVote(height int64, round, index int32, addr Address,
// 	blockID BlockID, time time.Time) *Vote {
// 	return &Vote{
// 		Type:             tmproto.SignedMsgType(2),
// 		Height:           height,
// 		Round:            round,
// 		BlockID:          blockID,
// 		Timestamp:        time,
// 		ValidatorAddress: addr,
// 		ValidatorIndex:   index,
// 	}
// }
//
// func randBlockID() BlockID {
// 	return BlockID{
// 		Hash: tmrand.Bytes(crypto.HashSize),
// 		PartSetHeader: PartSetHeader{
// 			Total: 1,
// 			Hash:  tmrand.Bytes(crypto.HashSize),
// 		},
// 	}
// }
