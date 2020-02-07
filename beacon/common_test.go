package beacon

import (
	"fmt"
	"github.com/go-kit/kit/log/term"
	abcicli "github.com/tendermint/tendermint/abci/client"
	"github.com/tendermint/tendermint/abci/example/counter"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	mempl "github.com/tendermint/tendermint/mempool"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	dbm "github.com/tendermint/tm-db"
	"os"
	"sort"
	"sync"
)

const (
	testSubscriber = "test-client"
)

var config *cfg.Config

// A cleanupFunc cleans up any config / test files created for a particular
// test.
type cleanupFunc func()

func ensureDir(dir string, mode os.FileMode) {
	if err := tmos.EnsureDir(dir, mode); err != nil {
		panic(err)
	}
}

func ResetConfig(name string) *cfg.Config {
	return cfg.ResetTestRoot(name)
}

func beaconLogger() log.Logger {
	return log.TestingLoggerWithColorFn(func(keyvals ...interface{}) term.FgBgColor {
		for i := 0; i < len(keyvals)-1; i += 2 {
			if keyvals[i] == "validator" {
				return term.FgBgColor{Fg: term.Color(uint8(keyvals[i+1].(int) + 1))}
			}
		}
		return term.FgBgColor{}
	}).With("module", "beacon")
}

func setCrypto() (generator string, groupPublicKey string, publicKeysVector StringVector, privateKeysVector StringVector){
	InitialiseMcl()

	// Information generic to all
	generator = "Fetch.ai Generator G"
	groupPublicKey = "1 13617830084396363337718434908852501458428164735125379368446532291036931854085 16638751093805422682570463783831011691772252489838589256909687996936790420765 5486323158821181154783464192503123612629027242960810671838168084617904106002 5100770784701939377150040548470418138755495771397245984025364438080419605892"

	publicKeysVector = NewStringVector()

	publicKeysVector.Add("1 1516668801111681192333855390709478388776976469635871255458339826120799995629 15404529425458480529934186883697956050977293669493681499925623406164981834678 2909596554463291940088543404664325870552709259638431744055983125541910737735 4556738626556924071180879837237263170421437053719948675689585886350044310797")
	publicKeysVector.Add("1 3704221052526089554640337799625431284241069449509753178319378880511260249112 16482428412860019658119201434864888642499711523158928674681528157581891142950 14271463299280191075489899760516851597662863145378360357767416191043697538562 10529005999825913612823609968014403303527425830688219143472065428954174433457")
	publicKeysVector.Add("1 10142327438716345424918983727546710953417724086728488935993615208644637432975 7248449580689388853293388155366304708565381580101208142814199673335048709192 14145028462281911032212016228766356111041462230042498369155150989624363250056 11744666229255773236044276247636062184616462117256576236564676831107656008974")
	publicKeysVector.Add("1 12205346776628556235494143052804720250559505650750859848258906907464000413257 5670375033225567291360576105475019849345682456357000720430210287982881351648 2488718167161835728179659071341250190481360204196012184684671416154312205916 15456091653783616539293690843847074257212709062535377897818432047446292814401")

	privateKeysVector = NewStringVector()

	privateKeysVector.Add("16534938823402113060673125801175683948490899769133048130634739353200748604473")
	privateKeysVector.Add("13127572624580735827410917700042683304450687818872394812692835249595633529202")
	privateKeysVector.Add("8977176623456312920391114204025776708798620755842542578785206958447612244442")
	privateKeysVector.Add("4083750820028844339613715313124964161534698580043491428911854479756684750193")

	return generator, groupPublicKey, publicKeysVector, privateKeysVector
}

func randBeaconNet(testName string, appFunc func() abci.Application, configOpts ...func(*cfg.Config)) ([]*EntropyGenerator, []*State, cleanupFunc) {
	nValidators := 4
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	logger := beaconLogger()

	entropyGenerators := make([]*EntropyGenerator, nValidators)
	configRootDirs := make([]string, 0, nValidators)
	css := make([]*State, nValidators)
	entropyChannels := make([]chan ComputedEntropy, nValidators)

	generator, groupPublicKey, publicKeysVector, privateKeysVector := setCrypto()

	for i := 0; i < nValidators; i++ {
		stateDB := dbm.NewMemDB() // each state needs its own db
		state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
		thisConfig := ResetConfig(fmt.Sprintf("%s_%d", testName, i))
		configRootDirs = append(configRootDirs, thisConfig.RootDir)
		for _, opt := range configOpts {
			opt(thisConfig)
		}

		index, _ := state.Validators.GetByAddress(privVals[i].GetPubKey().Address())
		aeonKeysTemp := NewDKGKeyInformation()
		defer DeleteDKGKeyInformation(aeonKeysTemp)

		aeonKeysTemp.SetPrivate_key(privateKeysVector.Get(int(index)))
		aeonKeysTemp.SetGroup_public_key(groupPublicKey)
		aeonKeysTemp.SetPublic_key_shares(publicKeysVector)

		// Initialise entropy channel
		entropyChannels[i] = make(chan ComputedEntropy, EntropyChannelCapacity)

		entropyGenerators[i] = NewEntropyGenerator(logger, state.Validators, privVals[i].GetPubKey().Address())
		entropyGenerators[i].SetGenesisEntropy([]byte("Fetch.ai Genesis Entropy"))
		entropyGenerators[i].SetAeonKeys(aeonKeysTemp, generator)
		entropyGenerators[i].SetComputedEntropyChannel(entropyChannels[i])

		app := appFunc()
		css[i] = newStateWithConfigAndBlockStore(thisConfig, state, privVals[i], app, stateDB)
		css[i].SetLogger(logger.With("validator", i, "module", "consensus"))
		css[i].SetEntropyChannel(entropyChannels[i])
	}

	defer DeleteStringVector(privateKeysVector)
	defer DeleteStringVector(publicKeysVector)

	return entropyGenerators, css, func() {
		for _, dir := range configRootDirs {
			os.RemoveAll(dir)
		}
	}
}

//-------------------------------------------------------------------------------
// genesis

func randGenesisDoc(numValidators int, randPower bool, minPower int64) (*types.GenesisDoc, []types.PrivValidator) {
	validators := make([]types.GenesisValidator, numValidators)
	privValidators := make([]types.PrivValidator, numValidators)
	for i := 0; i < numValidators; i++ {
		val, privVal := types.RandValidator(randPower, minPower)
		validators[i] = types.GenesisValidator{
			PubKey: val.PubKey,
			Power:  val.VotingPower,
		}
		privValidators[i] = privVal
	}
	sort.Sort(types.PrivValidatorsByAddress(privValidators))

	return &types.GenesisDoc{
		GenesisTime: tmtime.Now(),
		ChainID:     config.ChainID(),
		Validators:  validators,
	}, privValidators
}

//-------------------------------------------------------------------------------
// state

func newStateWithConfigAndBlockStore(
	thisConfig *cfg.Config,
	state sm.State,
	pv types.PrivValidator,
	app abci.Application,
	blockDB dbm.DB,
) *State {
	// Get BlockStore
	blockStore := store.NewBlockStore(blockDB)

	// one for mempool, one for consensus
	mtx := new(sync.Mutex)
	proxyAppConnMem := abcicli.NewLocalClient(mtx, app)
	proxyAppConnCon := abcicli.NewLocalClient(mtx, app)

	// Make Mempool
	mempool := mempl.NewCListMempool(thisConfig.Mempool, proxyAppConnMem, 0)
	mempool.SetLogger(log.TestingLogger().With("module", "mempool"))
	if thisConfig.Consensus.WaitForTxs() {
		mempool.EnableTxsAvailable()
	}

	// mock the evidence pool
	evpool := sm.MockEvidencePool{}

	// Make State
	stateDB := blockDB
	sm.SaveState(stateDB, state) //for save height 1's validators info
	blockExec := sm.NewBlockExecutor(stateDB, log.TestingLogger(), proxyAppConnCon, mempool, evpool)
	cs := NewState(thisConfig.Consensus, state, blockExec, blockStore, mempool, evpool)
	cs.SetLogger(log.TestingLogger().With("module", "consensus"))
	cs.SetPrivValidator(pv)

	eventBus := types.NewEventBus()
	eventBus.SetLogger(log.TestingLogger().With("module", "events"))
	eventBus.Start()
	cs.SetEventBus(eventBus)
	return cs
}

func newCounter() abci.Application {
	return counter.NewApplication(true)
}