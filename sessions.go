package main

import "time"

func newAccessToken(userID int) (string, error) {
	token := randAlphaNum(32)

	const insertSQL = `
    INSERT INTO sessions (user_id, access_token, creation_date) VALUES (?, ?, ?)`
	_, err := db().Exec(insertSQL, userID, token, time.Now().Unix())
	if err != nil {
		logErr(err)
		return "", err
	}

	return token, nil
}
