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

// DuplicateVoteWork contains work of a single validator signing two conflicting votes.
type DuplicateVoteWork struct {
	VoteA *Vote `json:"vote_a"`
	VoteB *Vote `json:"vote_b"`

	// abci specific information
	TotalVotingPower int64 `json:",string"`
	ValidatorPower   int64 `json:",string"`
	Timestamp        time.Time
}

// TypeTag implements the jsontypes.Tagged interface.
func (*DuplicateVoteWork) TypeTag() string { return "tendermint/DuplicateVoteWork" }

var _ Work = &DuplicateVoteWork{}

// NewDuplicateVoteWork creates DuplicateVoteWork with right ordering given
// two conflicting votes. If either of the votes is nil, the val set is nil or the voter is
// not in the val set, an error is returned
func NewDuplicateVoteWork(vote1, vote2 *Vote, blockTime time.Time, valSet *ValidatorSet,
) (*DuplicateVoteWork, error) {
	var voteA, voteB *Vote
	if vote1 == nil || vote2 == nil {
		return nil, errors.New("missing vote")
	}
	if valSet == nil {
		return nil, errors.New("missing validator set")
	}
	idx, val := valSet.GetByAddress(vote1.ValidatorAddress)
	if idx == -1 {
		return nil, errors.New("validator not in validator set")
	}

	if strings.Compare(vote1.BlockID.Key(), vote2.BlockID.Key()) == -1 {
		voteA = vote1
		voteB = vote2
	} else {
		voteA = vote2
		voteB = vote1
	}
	return &DuplicateVoteWork{
		VoteA:            voteA,
		VoteB:            voteB,
		TotalVotingPower: valSet.TotalVotingPower(),
		ValidatorPower:   val.VotingPower,
		Timestamp:        blockTime,
	}, nil
}

// ABCI returns the application relevant representation of the work
func (dve *DuplicateVoteWork) ABCI() []abci.Misbehavior {
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
func (dve *DuplicateVoteWork) Bytes() []byte {
	pbe := dve.ToProto()
	bz, err := pbe.Marshal()
	if err != nil {
		panic("marshaling duplicate vote work to bytes: " + err.Error())
	}

	return bz
}

// Hash returns the hash of the work.
func (dve *DuplicateVoteWork) Hash() []byte {
	return crypto.Checksum(dve.Bytes())
}

// Height returns the height of the infraction
func (dve *DuplicateVoteWork) Height() int64 {
	return dve.VoteA.Height
}

// String returns a string representation of the work.
func (dve *DuplicateVoteWork) String() string {
	return fmt.Sprintf("DuplicateVoteWork{VoteA: %v, VoteB: %v}", dve.VoteA, dve.VoteB)
}

// Time returns the time of the infraction
func (dve *DuplicateVoteWork) Time() time.Time {
	return dve.Timestamp
}

// ValidateBasic performs basic validation.
func (dve *DuplicateVoteWork) ValidateBasic() error {
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
func (dve *DuplicateVoteWork) ValidateABCI(
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
func (dve *DuplicateVoteWork) GenerateABCI(
	val *Validator,
	valSet *ValidatorSet,
	workTime time.Time,
) {
	dve.ValidatorPower = val.VotingPower
	dve.TotalVotingPower = valSet.TotalVotingPower()
	dve.Timestamp = workTime
}

// ToProto encodes DuplicateVoteWork to protobuf
func (dve *DuplicateVoteWork) ToProto() *tmproto.DuplicateVoteWork {
	voteB := dve.VoteB.ToProto()
	voteA := dve.VoteA.ToProto()
	tp := tmproto.DuplicateVoteWork{
		VoteA:            voteA,
		VoteB:            voteB,
		TotalVotingPower: dve.TotalVotingPower,
		ValidatorPower:   dve.ValidatorPower,
		Timestamp:        dve.Timestamp,
	}
	return &tp
}

// DuplicateVoteWorkFromProto decodes protobuf into DuplicateVoteWork
func DuplicateVoteWorkFromProto(pb *tmproto.DuplicateVoteWork) (*DuplicateVoteWork, error) {
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

	dve := &DuplicateVoteWork{
		VoteA:            vA,
		VoteB:            vB,
		TotalVotingPower: pb.TotalVotingPower,
		ValidatorPower:   pb.ValidatorPower,
		Timestamp:        pb.Timestamp,
	}

	return dve, dve.ValidateBasic()
}

//------------------------------------ LIGHT EVIDENCE --------------------------------------

// LightClientAttackWork is a generalized work that captures all forms of known attacks on
// a light client such that a full node can verify, propose and commit the work on-chain for
// punishment of the malicious validators. There are three forms of attacks: Lunatic, Equivocation
// and Amnesia. These attacks are exhaustive. You can find a more detailed overview of this at
// tendermint/docs/architecture/adr-047-handling-work-from-light-client.md
//
// CommonHeight is used to indicate the type of attack. If the height is different to the conflicting block
// height, then nodes will treat this as of the Lunatic form, else it is of the Equivocation form.
type LightClientAttackWork struct {
	ConflictingBlock *LightBlock
	CommonHeight     int64 `json:",string"`

	// abci specific information
	ByzantineValidators []*Validator // validators in the validator set that misbehaved in creating the conflicting block
	TotalVotingPower    int64        `json:",string"` // total voting power of the validator set at the common height
	Timestamp           time.Time    // timestamp of the block at the common height
}

// TypeTag implements the jsontypes.Tagged interface.
func (*LightClientAttackWork) TypeTag() string { return "tendermint/LightClientAttackWork" }

var _ Work = &LightClientAttackWork{}

// ABCI forms an array of abci.Misbehavior for each byzantine validator
func (l *LightClientAttackWork) ABCI() []abci.Misbehavior {
	abciEv := make([]abci.Misbehavior, len(l.ByzantineValidators))
	for idx, val := range l.ByzantineValidators {
		abciEv[idx] = abci.Misbehavior{
			Type:             abci.MisbehaviorType_LIGHT_CLIENT_ATTACK,
			Validator:        TM2PB.Validator(val),
			Height:           l.Height(),
			Time:             l.Timestamp,
			TotalVotingPower: l.TotalVotingPower,
		}
	}
	return abciEv
}

// Bytes returns the proto-encoded work as a byte array
func (l *LightClientAttackWork) Bytes() []byte {
	pbe, err := l.ToProto()
	if err != nil {
		panic("converting light client attack work to proto: " + err.Error())
	}
	bz, err := pbe.Marshal()
	if err != nil {
		panic("marshaling light client attack work to bytes: " + err.Error())
	}
	return bz
}

// GetByzantineValidators finds out what style of attack LightClientAttackWork was and then works out who
// the malicious validators were and returns them. This is used both for forming the ByzantineValidators
// field and for validating that it is correct. Validators are ordered based on validator power
func (l *LightClientAttackWork) GetByzantineValidators(commonVals *ValidatorSet,
	trusted *SignedHeader) []*Validator {
	var validators []*Validator
	// First check if the header is invalid. This means that it is a lunatic attack and therefore we take the
	// validators who are in the commonVals and voted for the lunatic header
	if l.ConflictingHeaderIsInvalid(trusted.Header) {
		for _, commitSig := range l.ConflictingBlock.Commit.Signatures {
			if commitSig.BlockIDFlag != BlockIDFlagCommit {
				continue
			}

			_, val := commonVals.GetByAddress(commitSig.ValidatorAddress)
			if val == nil {
				// validator wasn't in the common validator set
				continue
			}
			validators = append(validators, val)
		}
		sort.Sort(ValidatorsByVotingPower(validators))
		return validators
	} else if trusted.Commit.Round == l.ConflictingBlock.Commit.Round {
		// This is an equivocation attack as both commits are in the same round. We then find the validators
		// from the conflicting light block validator set that voted in both headers.
		// Validator hashes are the same therefore the indexing order of validators are the same and thus we
		// only need a single loop to find the validators that voted twice.
		for i := 0; i < len(l.ConflictingBlock.Commit.Signatures); i++ {
			sigA := l.ConflictingBlock.Commit.Signatures[i]
			if sigA.BlockIDFlag != BlockIDFlagCommit {
				continue
			}

			sigB := trusted.Commit.Signatures[i]
			if sigB.BlockIDFlag != BlockIDFlagCommit {
				continue
			}

			_, val := l.ConflictingBlock.ValidatorSet.GetByAddress(sigA.ValidatorAddress)
			validators = append(validators, val)
		}
		sort.Sort(ValidatorsByVotingPower(validators))
		return validators
	}
	// if the rounds are different then this is an amnesia attack. Unfortunately, given the nature of the attack,
	// we aren't able yet to deduce which are malicious validators and which are not hence we return an
	// empty validator set.
	return validators
}

// ConflictingHeaderIsInvalid takes a trusted header and matches it againt a conflicting header
// to determine whether the conflicting header was the product of a valid state transition
// or not. If it is then all the deterministic fields of the header should be the same.
// If not, it is an invalid header and constitutes a lunatic attack.
func (l *LightClientAttackWork) ConflictingHeaderIsInvalid(trustedHeader *Header) bool {
	return !bytes.Equal(trustedHeader.ValidatorsHash, l.ConflictingBlock.ValidatorsHash) ||
		!bytes.Equal(trustedHeader.NextValidatorsHash, l.ConflictingBlock.NextValidatorsHash) ||
		!bytes.Equal(trustedHeader.ConsensusHash, l.ConflictingBlock.ConsensusHash) ||
		!bytes.Equal(trustedHeader.AppHash, l.ConflictingBlock.AppHash) ||
		!bytes.Equal(trustedHeader.LastResultsHash, l.ConflictingBlock.LastResultsHash)

}

// Hash returns the hash of the header and the commonHeight. This is designed to cause hash collisions
// with work that have the same conflicting header and common height but different permutations
// of validator commit signatures. The reason for this is that we don't want to allow several
// permutations of the same work to be committed on chain. Ideally we commit the header with the
// most commit signatures (captures the most byzantine validators) but anything greater than 1/3 is
// sufficient.
// TODO: We should change the hash to include the commit, header, total voting power, byzantine
// validators and timestamp
func (l *LightClientAttackWork) Hash() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(buf, l.CommonHeight)
	bz := make([]byte, crypto.HashSize+n)
	copy(bz[:crypto.HashSize-1], l.ConflictingBlock.Hash().Bytes())
	copy(bz[crypto.HashSize:], buf)
	return crypto.Checksum(bz)
}

// Height returns the last height at which the primary provider and witness provider had the same header.
// We use this as the height of the infraction rather than the actual conflicting header because we know
// that the malicious validators were bonded at this height which is important for work expiry
func (l *LightClientAttackWork) Height() int64 {
	return l.CommonHeight
}

// String returns a string representation of LightClientAttackWork
func (l *LightClientAttackWork) String() string {
	return fmt.Sprintf(`LightClientAttackWork{
		ConflictingBlock: %v,
		CommonHeight: %d,
		ByzatineValidators: %v,
		TotalVotingPower: %d,
		Timestamp: %v}#%X`,
		l.ConflictingBlock.String(), l.CommonHeight, l.ByzantineValidators,
		l.TotalVotingPower, l.Timestamp, l.Hash())
}

// Time returns the time of the common block where the infraction leveraged off.
func (l *LightClientAttackWork) Time() time.Time {
	return l.Timestamp
}

// ValidateBasic performs basic validation such that the work is consistent and can now be used for verification.
func (l *LightClientAttackWork) ValidateBasic() error {
	if l.ConflictingBlock == nil {
		return errors.New("conflicting block is nil")
	}

	// this check needs to be done before we can run validate basic
	if l.ConflictingBlock.Header == nil {
		return errors.New("conflicting block missing header")
	}

	if l.TotalVotingPower <= 0 {
		return errors.New("negative or zero total voting power")
	}

	if l.CommonHeight <= 0 {
		return errors.New("negative or zero common height")
	}

	// check that common height isn't ahead of the height of the conflicting block. It
	// is possible that they are the same height if the light node witnesses either an
	// amnesia or a equivocation attack.
	if l.CommonHeight > l.ConflictingBlock.Height {
		return fmt.Errorf("common height is ahead of the conflicting block height (%d > %d)",
			l.CommonHeight, l.ConflictingBlock.Height)
	}

	if err := l.ConflictingBlock.ValidateBasic(l.ConflictingBlock.ChainID); err != nil {
		return fmt.Errorf("invalid conflicting light block: %w", err)
	}

	return nil
}

// ValidateABCI validates the ABCI component of the work by checking the
// timestamp, byzantine validators and total voting power all match. ABCI
// components are validated separately because they can be re generated if
// invalid.
func (l *LightClientAttackWork) ValidateABCI(
	commonVals *ValidatorSet,
	trustedHeader *SignedHeader,
	workTime time.Time,
) error {

	if evTotal, valsTotal := l.TotalVotingPower, commonVals.TotalVotingPower(); evTotal != valsTotal {
		return fmt.Errorf("total voting power from the work and our validator set does not match (%d != %d)",
			evTotal, valsTotal)
	}

	if l.Timestamp != workTime {
		return fmt.Errorf(
			"work has a different time to the block it is associated with (%v != %v)",
			l.Timestamp, workTime)
	}

	// Find out what type of attack this was and thus extract the malicious
	// validators. Note, in the case of an Amnesia attack we don't have any
	// malicious validators.
	validators := l.GetByzantineValidators(commonVals, trustedHeader)

	// Ensure this matches the validators that are listed in the work. They
	// should be ordered based on power.
	if validators == nil && l.ByzantineValidators != nil {
		return fmt.Errorf(
			"expected nil validators from an amnesia light client attack but got %d",
			len(l.ByzantineValidators),
		)
	}

	if exp, got := len(validators), len(l.ByzantineValidators); exp != got {
		return fmt.Errorf("expected %d byzantine validators from work but got %d", exp, got)
	}

	for idx, val := range validators {
		if !bytes.Equal(l.ByzantineValidators[idx].Address, val.Address) {
			return fmt.Errorf(
				"work contained an unexpected byzantine validator address; expected: %v, got: %v",
				val.Address, l.ByzantineValidators[idx].Address,
			)
		}

		if l.ByzantineValidators[idx].VotingPower != val.VotingPower {
			return fmt.Errorf(
				"work contained unexpected byzantine validator power; expected %d, got %d",
				val.VotingPower, l.ByzantineValidators[idx].VotingPower,
			)
		}
	}

	return nil
}

// GenerateABCI populates the ABCI component of the work: the timestamp,
// total voting power and byantine validators
func (l *LightClientAttackWork) GenerateABCI(
	commonVals *ValidatorSet,
	trustedHeader *SignedHeader,
	workTime time.Time,
) {
	l.Timestamp = workTime
	l.TotalVotingPower = commonVals.TotalVotingPower()
	l.ByzantineValidators = l.GetByzantineValidators(commonVals, trustedHeader)
}

// ToProto encodes LightClientAttackWork to protobuf
func (l *LightClientAttackWork) ToProto() (*tmproto.LightClientAttackWork, error) {
	conflictingBlock, err := l.ConflictingBlock.ToProto()
	if err != nil {
		return nil, err
	}

	byzVals := make([]*tmproto.Validator, len(l.ByzantineValidators))
	for idx, val := range l.ByzantineValidators {
		valpb, err := val.ToProto()
		if err != nil {
			return nil, err
		}
		byzVals[idx] = valpb
	}

	return &tmproto.LightClientAttackWork{
		ConflictingBlock:    conflictingBlock,
		CommonHeight:        l.CommonHeight,
		ByzantineValidators: byzVals,
		TotalVotingPower:    l.TotalVotingPower,
		Timestamp:           l.Timestamp,
	}, nil
}

// LightClientAttackWorkFromProto decodes protobuf
func LightClientAttackWorkFromProto(lpb *tmproto.LightClientAttackWork) (*LightClientAttackWork, error) {
	if lpb == nil {
		return nil, errors.New("empty light client attack work")
	}

	conflictingBlock, err := LightBlockFromProto(lpb.ConflictingBlock)
	if err != nil {
		return nil, err
	}

	byzVals := make([]*Validator, len(lpb.ByzantineValidators))
	for idx, valpb := range lpb.ByzantineValidators {
		val, err := ValidatorFromProto(valpb)
		if err != nil {
			return nil, err
		}
		byzVals[idx] = val
	}

	l := &LightClientAttackWork{
		ConflictingBlock:    conflictingBlock,
		CommonHeight:        lpb.CommonHeight,
		ByzantineValidators: byzVals,
		TotalVotingPower:    lpb.TotalVotingPower,
		Timestamp:           lpb.Timestamp,
	}

	return l, l.ValidateBasic()
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
	case *DuplicateVoteWork:
		pbev := evi.ToProto()
		return &tmproto.Work{
			Sum: &tmproto.Work_DuplicateVoteWork{
				DuplicateVoteWork: pbev,
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
	case *tmproto.Work_DuplicateVoteWork:
		return DuplicateVoteWorkFromProto(evi.DuplicateVoteWork)
	case *tmproto.Work_LightClientAttackWork:
		return LightClientAttackWorkFromProto(evi.LightClientAttackWork)
	default:
		return nil, errors.New("work is not recognized")
	}
}

func init() {
	jsontypes.MustRegister((*DuplicateVoteWork)(nil))
	jsontypes.MustRegister((*LightClientAttackWork)(nil))
}

//-------------------------------------------- ERRORS --------------------------------------

// ErrInvalidWork wraps a piece of work and the error denoting how or why it is invalid.
type ErrInvalidWork struct {
	Work Work
	Reason   error
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
// func NewMockDuplicateVoteWork(ctx context.Context, height int64, time time.Time, chainID string) (*DuplicateVoteWork, error) {
// 	val := NewMockPV()
// 	return NewMockDuplicateVoteWorkWithValidator(ctx, height, time, val, chainID)
// }
//
// // assumes voting power to be 10 and validator to be the only one in the set
// func NewMockDuplicateVoteWorkWithValidator(ctx context.Context, height int64, time time.Time, pv PrivValidator, chainID string) (*DuplicateVoteWork, error) {
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
// 	ev, err := NewDuplicateVoteWork(voteA, voteB, time, NewValidatorSet([]*Validator{val}))
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
