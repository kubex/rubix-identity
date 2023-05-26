package oathkeeper

type identityTrait struct {
	Email string `json:"email"`
	Name  struct {
		First string `json:"first"`
		Last  string `json:"last"`
	}
}
