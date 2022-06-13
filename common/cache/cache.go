package cache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// The global cache
var _cache = cache.New(30*time.Minute, 10*time.Minute)

// GetCache returns the cache
func GetCache() *cache.Cache {
	return _cache
}
