package vault

func Init() (err error) {
	Primary = &Vault{}

	err = Primary.Init()
	if err != nil {
		return
	}

	return
}
