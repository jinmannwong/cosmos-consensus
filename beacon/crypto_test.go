package beacon

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/types"
)

func TestCryptoSign(t *testing.T) {
	cabinetSize := uint64(4)

	directory := "test_keys/"
	aeonExecUnit := NewAeonExecUnit(directory + "0.txt")
	defer DeleteAeonExecUnit(aeonExecUnit)

	assert.True(t, aeonExecUnit.CanSign())
	message := "HelloWorld"
	signature := aeonExecUnit.Sign(message)
	assert.True(t, aeonExecUnit.Verify(message, signature, uint64(0)))

	// Collect signatures in map
	signatureShares := NewIntStringMap()
	defer DeleteIntStringMap(signatureShares)
	signatureShares.Set(0, signature)

	// Create aeon keys for each cabinet member and entropy generators
	for i := uint64(1); i < cabinetSize; i++ {
		aeonExecUnitTemp := NewAeonExecUnit(directory + strconv.Itoa(int(i)) + ".txt")
		defer DeleteAeonExecUnit(aeonExecUnitTemp)

		assert.True(t, aeonExecUnitTemp.CanSign())
		signatureTemp := aeonExecUnitTemp.Sign(message)
		assert.True(t, len([]byte(signatureTemp)) <= types.MaxEntropyShareSize)
		assert.True(t, aeonExecUnitTemp.Verify(message, signatureTemp, i))

		signatureShares.Set(int(i), signatureTemp)
	}
	groupSignature := aeonExecUnit.ComputeGroupSignature(signatureShares)
	assert.True(t, len([]byte(groupSignature)) <= types.MaxThresholdSignatureSize)
	assert.True(t, aeonExecUnit.VerifyGroupSignature(message, groupSignature))
}

func TestCryptoNonValidator(t *testing.T) {
	aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
	defer DeleteAeonExecUnit(aeonExecUnit)

	assert.False(t, aeonExecUnit.CanSign())
}
