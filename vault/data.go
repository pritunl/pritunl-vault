package vault

type Input struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	Collection string `json:"c"`
	Id         string `json:"i"`
	Key        string `json:"k"`
	Value      string `json:"v"`
	Signature  string `json:"s"`
}

type Output struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	Collection string `json:"c"`
	Id         string `json:"i"`
	Key        string `json:"k"`
	Value      string `json:"v"`
	Signature  string `json:"s"`
}

type ServerKey struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	HostKey   string `json:"h"`
	ServerKey string `json:"s"`
}

type MasterKey struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	HostSecret   string `json:"h"`
	ServerSecret string `json:"s"`
	ClientSecret string `json:"c"`
	MasterNonce  string `json:"o"`
	MasterKey    string `json:"m"`
}

type MasterKeyData struct {
	MasterKey     string `json:"m"`
	Authorization string `json:"a"`
}

type Payload struct {
	Nonce string `json:"n"`
	Data  string `json:"d"`
}
