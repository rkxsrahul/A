package database

import (
	"encoding/json"

	"git.xenonstack.com/util/continuous-security-backend/config"
)

// SaveRow is a method to perform insert query by converting map into result
func SaveRow(mapd map[string]interface{}, uuid, header, method string) {

	db := config.DB
	// db = db.Debug()

	var result ScanResult
	result.UUID = uuid
	result.Method = method
	result.CommandName = header
	scanBytes, _ := json.Marshal(mapd)
	result.Result = string(scanBytes)
	db.Create(&result)
}
