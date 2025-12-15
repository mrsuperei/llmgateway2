package store

import "github.com/jackc/pgx/v5/pgxpool"

type Store struct {
	pool *pgxpool.Pool

	users   *UsersRepo
	prov    *ProvidersRepo
	creds   *CredentialsRepo
	limits  *LimitsRepo
	cnt     *CountersRepo
	routes  *RoutesRepo
	states  *OAuthStateRepo
}

func New(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool}
	s.users = &UsersRepo{pool: pool}
	s.prov = &ProvidersRepo{pool: pool}
	s.creds = &CredentialsRepo{pool: pool}
	s.limits = &LimitsRepo{pool: pool}
	s.cnt = &CountersRepo{pool: pool}
	s.routes = &RoutesRepo{pool: pool}
	s.states = &OAuthStateRepo{pool: pool}
	return s
}

func (s *Store) Users() *UsersRepo           { return s.users }
func (s *Store) Providers() *ProvidersRepo   { return s.prov }
func (s *Store) Credentials() *CredentialsRepo { return s.creds }
func (s *Store) Limits() *LimitsRepo         { return s.limits }
func (s *Store) Counters() *CountersRepo     { return s.cnt }
func (s *Store) Routes() *RoutesRepo         { return s.routes }
func (s *Store) OAuthStates() *OAuthStateRepo { return s.states }
