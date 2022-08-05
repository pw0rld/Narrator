package kvstore

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"crypto/ed25519"
	"io/ioutil"

	dbm "github.com/tendermint/tm-db"

	"github.com/tendermint/tendermint/abci/example/code"
	"github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/version"
	
)

var (
	stateKey        = []byte("stateKey")
	kvPairPrefixKey = []byte("kvPairKey:")

	ProtocolVersion uint64 = 0x1
)

type State struct {
	db      dbm.DB
	Size    int64  `json:"size"`
	Height  int64  `json:"height"`
	AppHash []byte `json:"app_hash"`
}

func loadState(db dbm.DB) State {
	var state State
	state.db = db
	stateBytes, err := db.Get(stateKey)
	if err != nil {
		panic(err)
	}
	if len(stateBytes) == 0 {
		return state
	}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		panic(err)
	}
	return state
}

func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	err = state.db.Set(stateKey, stateBytes)
	if err != nil {
		panic(err)
	}
}

func prefixKey(key []byte) []byte {
	return append(kvPairPrefixKey, key...)
}

//---------------------------------------------------

var _ types.Application = (*Application)(nil)

type Application struct {
	types.BaseApplication

	state        State
	RetainBlocks int64 // blocks to retain after commit (via ResponseCommit.RetainHeight)
}

func NewApplication() *Application {
	state := loadState(dbm.NewMemDB())
	return &Application{state: state}
}

func (app *Application) Info(req types.RequestInfo) (resInfo types.ResponseInfo) {
	return types.ResponseInfo{
		Data:             fmt.Sprintf("{\"size\":%v}", app.state.Size),
		Version:          version.ABCIVersion,
		AppVersion:       ProtocolVersion,
		LastBlockHeight:  app.state.Height,
		LastBlockAppHash: app.state.AppHash,
	}
}

// tx is either "key=value" or just arbitrary bytes
func (app *Application) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	var key, value string

	parts := bytes.Split(req.Tx, []byte("="))
	if len(parts) == 2 {
		key, value = string(parts[0]), string(parts[1])
	} else {
		key, value = string(req.Tx), string(req.Tx)
	}

	err := app.state.db.Set(prefixKey([]byte(key)), []byte(value))
	if err != nil {
		panic(err)
	}
	app.state.Size++

	events := []types.Event{
		{
			Type: "app",
			Attributes: []types.EventAttribute{
				{Key: "creator", Value: "Cosmoshi Netowoko", Index: true},
				{Key: "key", Value: key, Index: true},
				{Key: "index_key", Value: "index is working", Index: true},
				{Key: "noindex_key", Value: "index is working", Index: false},
			},
		},
	}

	return types.ResponseDeliverTx{Code: code.CodeTypeOK, Events: events}
}

func (app *Application) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	return types.ResponseCheckTx{Code: code.CodeTypeOK, GasWanted: 1}
}

func (app *Application) Commit() types.ResponseCommit {
	// Using a memdb - just return the big endian size of the db
	appHash := make([]byte, 8)
	binary.PutVarint(appHash, app.state.Size)
	app.state.AppHash = appHash
	app.state.Height++
	saveState(app.state)

	resp := types.ResponseCommit{Data: appHash}
	if app.RetainBlocks > 0 && app.state.Height >= app.RetainBlocks {
		resp.RetainHeight = app.state.Height - app.RetainBlocks + 1
	}
	return resp
}

// Returns an associated value or nil if missing.
func (app *Application) Query(reqQuery types.RequestQuery) (resQuery types.ResponseQuery) {
	if reqQuery.Prove {
		value, err := app.state.db.Get(prefixKey(reqQuery.Data))
		if err != nil {
			panic(err)
		}
		if value == nil {
			resQuery.Log = "does not exist"
		} else {
			resQuery.Log = "exists"
		}
		resQuery.Index = -1 // TODO make Proof return index
		resQuery.Key = reqQuery.Data
		resQuery.Value = value
		resQuery.Height = app.state.Height

		return
	}

	resQuery.Key = reqQuery.Data
	value, err := app.state.db.Get(prefixKey(reqQuery.Data))
	if err != nil {
		panic(err)
	}
	if value == nil {
		resQuery.Log = "does not exist"
	} else {
		resQuery.Log = "exists"
	}
	resQuery.Value = value
	resQuery.Height = app.state.Height
	// hash_data := resQuery.Log + base64.URLEncoding.EncodeToString(resQuery.Value) + fmt.Sprintf("%d", resQuery.Height)
	hash_data := resQuery.Log  + fmt.Sprintf("%d", resQuery.Height)
	_, ecd25519_priv_key := Read()
	ecd25519_priv_key_bytes, _ := base64.StdEncoding.DecodeString(ecd25519_priv_key)
	signatureBytes := ed25519.Sign(ed25519.PrivateKey(ecd25519_priv_key_bytes), []byte(hash_data))
	resQuery.Codespace = base64.StdEncoding.EncodeToString(signatureBytes)
	return resQuery
}
type pub_key struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ecd25519_key struct {
	Address  string  `json:"address"`
	Pub_key  pub_key `json:"pub_key"`
	Priv_key pub_key `json:"priv_key"`
}

func Read() (string, string) {
	f, err := ioutil.ReadFile("/root/.tendermint/config/priv_validator_key.json") // TODO 多个节点之后可能需要改动
	if err != nil {
		fmt.Println("read fail", err)

	}
	var Pkey ecd25519_key
	json.Unmarshal([]byte(f), &Pkey)
	return Pkey.Pub_key.Value, Pkey.Priv_key.Value
}