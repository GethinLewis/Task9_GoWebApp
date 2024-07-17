package main

import (
	"Task9_GoWebApp/initializers"
	"Task9_GoWebApp/middleware"
	"Task9_GoWebApp/models"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDatabase()
}

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     []string{"http://gethintest.enterpriselocal.com:8080", "http://localhost"},
		AllowHeaders:     []string{"Authorization", "content-type"},
	}))

	r.POST("/adduser", addUser)

	r.POST("/addreview", middleware.RequireAuth, addReview)

	r.GET("/login", authenticateLogin)

	r.GET("/validate", middleware.RequireAuth, validate)

	r.GET("/checkusername", checkUsername)

	r.GET("/getusername", getUsername)

	r.GET("/getfilms", getFilms)

	r.GET("/getfilm", getFilm)

	r.GET("getallreviews", getAllReviews)

	r.GET("getreviews", getReviews)

	routeraddress := fmt.Sprintf("localhost:%v", os.Getenv("PORT"))
	err := r.Run(routeraddress)
	if err != nil {
		log.Fatal(err)
	}
}

func hashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Fatal(err)
	}

	return string(bytes)
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Fatal(err)
	}
	return err == nil
}

func addUser(c *gin.Context) {
	// Get user data from request body
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Fatal(err)
	}

	type Login struct {
		Username string
		Password string
	}

	login := Login{}

	// Put json request body into login struct
	json.Unmarshal(requestBody, &login)

	// Hash password
	login.Password = hashPassword(login.Password)

	user := models.User{Username: login.Username, Password: login.Password}

	// Add User details to database
	result := initializers.DB.Create(&user)
	if result.Error != nil {
		log.Fatal(result.Error)
	}

	c.String(http.StatusOK, "Posted")
}

func addReview(c *gin.Context) {
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Fatal(err)
	}

	type Review struct {
		Userid      string `json:"userid"`
		Filmid      string `json:"filmid"`
		Starrating  string `json:"starrating"`
		Reviewtitle string `json:"reviewtitle"`
		Reviewbody  string `json:"reviewbody"`
	}

	review := Review{}
	json.Unmarshal(requestBody, &review)

	userid, _ := c.Get("userID")
	fmt.Println(userid)

	intUserid := userid.(uint)

	floatStarrating, err := strconv.ParseFloat(review.Starrating, 32)
	if err != nil {
		log.Fatal(err)
	}

	post := models.Post{
		User_id:     uint(intUserid),
		Film_id:     review.Filmid,
		Star_rating: float32(floatStarrating),
		Post_title:  review.Reviewtitle,
		Body:        review.Reviewbody,
	}

	result := initializers.DB.Create(&post)
	if result.Error != nil {
		log.Fatal(result.Error)
	}

	c.String(http.StatusOK, "Posted")
}

func authenticateLogin(c *gin.Context) {
	// Get username and password
	var input_username string = c.Query("username")
	var input_password string = c.Query("password")

	var user = models.User{}

	/* 	type LoginResponse struct {
	   		UserID    uint   `gorm:"user_id" json:"user_id"`
	   		Username  string `gorm:"username" json:"username"`
	   		LoginPass bool   `gorm:"-"`
	   	}

	   	var loginResponse = LoginResponse{} */

	// Look up specified user
	result := initializers.DB.Where("username = ?", input_username).Find(&user)
	if result.Error != nil {
		log.Fatal(result.Error)
	}

	// Compate sent in password with saved password
	if (user == models.User{}) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid username or password",
		})
		return
	} else {

		if checkPasswordHash(input_password, user.Password) && !user.Deleted {
			// Generate JWT token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": user.User_id,
				"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
			})

			// Sign and get the encoded token as a string
			tokenString, err := token.SignedString([]byte(os.Getenv("JWTKEY")))
			if err != nil {
				fmt.Println(err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Failed to sign JWT Token",
				})

				return
			}

			// Send token back
			c.String(http.StatusOK, tokenString)

		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid username or password",
			})
			return
		}
	}
}

func validate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "I'm Loggeed In",
	})
}

func checkUsername(c *gin.Context) {
	var username string = c.Query("username")
	var user = models.User{}

	result := initializers.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			fmt.Println("y")
			c.String(http.StatusOK, "y")
		} else {
			log.Fatal(result.Error)
		}
	} else {
		fmt.Println("n")
		c.String(http.StatusOK, "n")
	}
}

func getUsername(c *gin.Context) {
	var userID string = c.Query("userid")
	var users []models.User

	type Username struct {
		Username string `gorm:"username" json:"username"`
	}

	var username = Username{}

	initializers.DB.Model(&users).Where("user_id = ?", userID).Find(&username)
	c.JSON(http.StatusOK, username)
}

func getFilms(c *gin.Context) {
	var searchTerm string = c.Query("searchterm")

	type FilmSearch struct {
		Search []struct {
			Title  string `json:"Title"`
			Year   string `json:"Year"`
			ImdbID string `json:"imdbID"`
			Type   string `json:"Type"`
			Poster string `json:"Poster"`
		} `json:"Search"`
		TotalResults string `json:"totalResults"`
		Response     string `json:"Response"`
	}

	var oldbRequest string = fmt.Sprintf("http://omdbapi.com/?apikey=%s&s=%s&type=movie", os.Getenv("APIKEY"), searchTerm)
	resp, err := http.Get(oldbRequest)
	if err != nil {
		log.Fatal(err)
	}

	filmData, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	search := FilmSearch{}
	json.Unmarshal(filmData, &search)
	c.JSON(http.StatusOK, search)
}

func getFilm(c *gin.Context) {
	var filmID string = c.Query("filmid")

	type FilmResponse struct {
		Title    string `json:"Title"`
		Year     string `json:"Year"`
		Rated    string `json:"Rated"`
		Released string `json:"Released"`
		Runtime  string `json:"Runtime"`
		Genre    string `json:"Genre"`
		Director string `json:"Director"`
		Writer   string `json:"Writer"`
		Actors   string `json:"Actors"`
		Plot     string `json:"Plot"`
		Language string `json:"Language"`
		Country  string `json:"Country"`
		Awards   string `json:"Awards"`
		Poster   string `json:"Poster"`
		Ratings  []struct {
			Source string `json:"Source"`
			Value  string `json:"Value"`
		} `json:"Ratings"`
		Metascore  string `json:"Metascore"`
		ImdbRating string `json:"imdbRating"`
		ImdbVotes  string `json:"imdbVotes"`
		ImdbID     string `json:"imdbID"`
		Type       string `json:"Type"`
		DVD        string `json:"DVD"`
		BoxOffice  string `json:"BoxOffice"`
		Production string `json:"Production"`
		Website    string `json:"Website"`
		Response   string `json:"Response"`
	}

	var oldbRequest string = fmt.Sprintf("http://omdbapi.com/?apikey=%s&i=%s&type=movie", os.Getenv("APIKEY"), filmID)
	resp, err := http.Get(oldbRequest)
	if err != nil {
		log.Fatal(err)
	}

	filmData, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	data := FilmResponse{}
	json.Unmarshal(filmData, &data)
	c.JSON(http.StatusOK, data)
}

func getAllReviews(c *gin.Context) {
	var reviews []models.Post

	initializers.DB.Find(&reviews)
	c.JSON(http.StatusOK, reviews)
}

func getReviews(c *gin.Context) {
	var filmID string = c.Query("filmid")
	var reviews []models.Post

	initializers.DB.Where("film_id = ?", filmID).Find(&reviews)
	c.JSON(http.StatusOK, reviews)
}
