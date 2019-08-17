package vault

type Item struct {
	Collection string `json:"c"`
	Id         string `json:"i"`
	Key        string `json:"k"`
	Value      string `json:"v"`
	Signature  string `json:"s"`
}

type Data struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	Items []*Item `json:"i"`
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
	CryptoKeys   string `json:"k"`
}

type MasterKeyData struct {
	MasterKey     string `json:"m"`
	Authorization string `json:"a"`
}

type CryptoKeys struct {
	AesKey  string `json:"e"`
	HmacKey string `json:"h"`

	Authorization string `json:"a"`
}

type CryptoKeysData struct {
	Nonce         string `json:"n"`
	Timestamp     int64  `json:"t"`
	Authorization string `json:"a"`

	CryptoKeys string `json:"k"`
}

type Payload struct {
	Nonce string `json:"n"`
	Data  string `json:"d"`
}
