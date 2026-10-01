package user

import "errors"

var ErrEmailExists = errors.New("email already exists")

type Store struct {
	users  []User
	nextID int
}

func NewStore() *Store {
	return &Store{
		users:  make([]User, 0),
		nextID: 1,
	}
}

func (s *Store) Create(email, passwordHash string) (User, error) {
	for _, u := range s.users {
		if u.Email == email {
			return User{}, ErrEmailExists
		}
	}

	newUser := User{
		ID:           s.nextID,
		Email:        email,
		PasswordHash: passwordHash,
	}

	s.users = append(s.users, newUser)
	s.nextID++

	return newUser, nil
}

func (s *Store) FindByEmail(email string) (User, error) {
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}

	return User{}, errors.New("user not found")
}
