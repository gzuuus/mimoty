package main

func CreateSubkeysTable() error {
	_, err := subkeyDB.Exec(`
        CREATE TABLE IF NOT EXISTS subkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pubkey TEXT NOT NULL UNIQUE,
            privkey TEXT NOT NULL,
            name TEXT,
            allowed_kinds TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    `)
	return err
}
