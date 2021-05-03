package service

import (
	"context"
	"errors"

	"github.com/realjf/oauth2/model"
)

var (
	ErrUserNotExist = errors.New("username is not exist")
	ErrPassword     = errors.New("invalid password")
)

type UserDetailsService interface {
	GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error)
}

type InMemoryUserDetailsService struct {
	userDetailsDict map[string]*model.UserDetails
}

func (service *InMemoryUserDetailsService) GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error) {
	// 根据username 获取用户信息
	userDetails, ok := service.userDetailsDict[username]
	if ok {
		// 比较password是否匹配
		if userDetails.Password == password {
			return userDetails, nil
		} else {
			return nil, ErrPassword
		}
	} else {
		return nil, ErrUserNotExist
	}
}

func NewInMemoryUserDetailsService(userDetailsList []*model.UserDetails) *InMemoryUserDetailsService {
	userDetailsDict := make(map[string]*model.UserDetails)

	if userDetailsDict != nil {
		for _, value := range userDetailsList {
			userDetailsDict[value.Username] = value
		}
	}

	return &InMemoryUserDetailsService{
		userDetailsDict: userDetailsDict,
	}
}
