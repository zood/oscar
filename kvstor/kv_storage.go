package kvstor

// Provider is the set of functionality required by oscar of a persistent
// key-value storage system.
type Provider interface {
	DropPackage(pkg []byte, boxID []byte) error
	InsertIds(userID int64, pubID []byte) error
	PickUpPackage(boxID []byte) ([]byte, error)
	PublicIDFromUserID(userID int64) ([]byte, error)
	UserIDFromPublicID(pubID []byte) (int64, error)
}
