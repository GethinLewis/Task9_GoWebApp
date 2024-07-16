package models

type User struct {
	User_id  uint   `gorm:"primaryKey" json:"user_id"`
	Username string `gorm:"username" json:"username"`
	Password string `gorm:"password" json:"password"`
	Deleted  bool   `gorm:"deleted" json:"deleted"`
}

type Post struct {
	Post_id     uint    `gorm:"primaryKey" json:"post_id"`
	Film_id     string  `gorm:"film_id" json:"film_id"`
	User_id     uint    `gorm:"user_id" json:"user_id"`
	Star_rating float32 `gorm:"star_rating" json:"star_rating"`
	Post_title  string  `gorm:"post_title" json:"post_title"`
	Body        string  `gorm:"body" json:"body"`
	Posted      string  `gorm:"default:CURRENT_TIMESTAMP()" json:"posted"`
	Deleted     bool    `gorm:"deleted" json:"deleted"`
}
