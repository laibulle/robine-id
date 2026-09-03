package crypto

import "golang.org/x/crypto/bcrypt"

type Bcrypt struct{ Cost int }

func (b Bcrypt) Compare(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (b Bcrypt) Hash(password string) (string, error) {
	cost := b.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(hash), err
}
