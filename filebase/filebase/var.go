package filebase

var Settings = struct {
	Addr             string `json:"address"`
	CertPath         string `json:"cert_path"`
	KeyPath          string `json:"key_path"`
	TLS              bool   `json:"tls"`
	LogErrors        bool   `json:"log_errors"`
	LogSuccess       bool   `json:"log_success"`
	MaxFileSize      int    `json:"max_file_size"`
	MaxFilesCount    int    `json:"max_files_count"`
	MaxAccountsCount int    `json:"max_accounts_count"`
}{
	Addr:             "0.0.0.0:4097",
	TLS:              false,
	LogErrors:        true,
	LogSuccess:       true,
	MaxFileSize:      8192,
	MaxFilesCount:    100,
	MaxAccountsCount: 100,
}
