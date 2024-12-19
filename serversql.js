require('dotenv').config()
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({ origin: ["http://localhost:3000" , "http://localhost:3001"] , credentials: true }));

let favorites = [];

// Setting SQl
const db = mysql.createConnection({
    host: "localhost",  
    user: "root",      
    password: "1234",   
    database: "turbobids" 
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to database');
});

// api page register
app.post('/api/auth/checkuser', (req, res) => {
    const { email } = req.body;
    console.log('Checking user with email:', email);

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Error in database query:', err);
            return res.status(500).json({ error: 'Database query failed' });
        }
        if (results.length > 0) {
            console.log('User exists:', results[0]);
            return res.json({ user: true });
        } else {
            console.log('User does not exist');
            return res.json({ user: false });
        }
    });
});

// api page register
app.post('/api/auth/register', async (req, res) => {
    const { username, firstname, lastname, email, password } = req.body;

    if (!username || !firstname || !lastname || !email || !password) {
        console.log('Missing fields for registration');
        return res.status(400).json({ error: 'Please complete all fields' });
    }

    db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, results) => {
        if (err) {
            console.error('Database query failed:', err);
            return res.status(500).json({ error: 'Database query failed' });
        }
        if (results.length > 0) {
            console.log('User already exists with email or username:', email, username);
            return res.status(400).json({ error: 'User already exists with this email or username' });
        }

        try {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password + "1234", saltRounds);
            console.log('Hashed password for new user:', hashedPassword);

            db.query(
                'INSERT INTO users (username, firstname, lastname, email, password) VALUES (?, ?, ?, ?, ?)',
                [username, firstname, lastname, email, hashedPassword],
                (err, results) => {
                    if (err) {
                        console.error('Error during registration:', err);
                        return res.status(500).json({ error: 'Registration failed' });
                    }
                    console.log('User registered successfully:', results);
                    return res.status(200).json({ message: 'User registered successfully' });
                }
            );
        } catch (err) {
            console.error('Error hashing password:', err);
            res.status(500).json({ error: 'Error during registration' });
        }
    });
});


// api page login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        console.log('Missing email or password for login');
        return res.status(400).json({ error: 'Please enter both email and password' });
    }

    console.log('Logging in user with email:', email);

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Error in database query:', err);
            return res.status(500).json({ error: 'Database query failed' });
        }

        if (results.length === 0) {
            console.log('User does not exist:', email);
            return res.status(400).json({ error: 'User does not exist' });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password + "1234", user.password);

        if (!isMatch) {
            console.log('Invalid password for user:', email);
            return res.status(400).json({ error: 'Invalid password' });
        }

        const token = jwt.sign(
            { id: user.UserID, email: user.email },
            process.env.JWT_SECRETKEY, 
            { expiresIn: '20m' } 
        );
        console.log(token);
        res.cookie("token", token, { httpOnly: true });

        console.log('Generated JWT token for user:', email);
        return res.status(200).json({
            message: 'Login successful',
            token: token
        });
    });
});


// api page updateuser
app.post("/api/user/userupdate", async (req, res) => {
    const { firstName, lastName, Username, currentPassword, newPassword, UserID } = req.body;
    console.log(firstName, lastName, Username, currentPassword, newPassword, UserID);


    if (!UserID || (!firstName && !lastName && !Username && !newPassword)) {
        return res.status(400).json({ error: "Please provide required fields" });
    }

    try {

        db.query("SELECT * FROM users WHERE UserID = ?", [UserID], async (err, results) => {
            if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ error: "Database error occurred" });
            }


            if (results.length === 0) {
                return res.status(404).json({ error: "User not found" });
            }

            const user = results[0];


            const isPasswordCorrect = await bcrypt.compare(currentPassword + "1234", user.password);
            if (!isPasswordCorrect) {
                return res.status(400).json({ error: "Current password is incorrect" });
            }


            const updates = {};
            if (firstName) updates.firstname = firstName;
            if (lastName) updates.lastname = lastName;
            if (Username) updates.Username = Username;


            if (newPassword) {
                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(newPassword + "1234", saltRounds);
                updates.password = hashedPassword;
            }


            const updateFields = Object.keys(updates).map((key) => `${key} = ?`).join(", ");
            const updateValues = Object.values(updates);

            db.query(
                `UPDATE users SET ${updateFields} WHERE UserID = ?`,
                [...updateValues, UserID],
                (err, results) => {
                    if (err) {
                        console.error("Error updating user:", err);
                        return res.status(500).json({ error: "Failed to update user" });
                    }
                    return res.status(200).json({ message: "Profile updated successfully" });
                }
            );
        });
    } catch (error) {
        console.error("Unexpected error:", error);
        res.status(500).json({ error: "An unexpected error occurred" });
    }
});

//api page adminpanel
app.get('/api/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
      if (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Error fetching users' });
        return;
      }
      res.json(results);
    });
  });

//api page adminpanel
app.post('/api/addCar', (req, res) => {
    const newCar = req.body;
  
    // เริ่มการทำธุรกรรม
    db.beginTransaction(err => {
      if (err) {
        return res.status(500).send('Transaction failed');
      }
  
      // 1. Insert into car table
      const carSql = `
        INSERT INTO car
        (car_brand, car_model, car_rear, car_color, car_status, car_details, car_year, car_price,
        odometer, primary_damage, cylinders, transmission, drive, fuel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const carValues = [
        newCar.car_brand, newCar.car_model, newCar.car_rear, newCar.car_color, newCar.car_status,
        newCar.car_details, newCar.car_year, newCar.car_price, newCar.odometer, newCar.primary_damage,
        newCar.cylinders, newCar.transmission, newCar.drive, newCar.fuel
      ];
  
      db.query(carSql, carValues, (err, carResult) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).send('Error inserting car data');
          });
        }
  
        const car_ID = carResult.insertId; // เก็บ car_ID ที่ได้จากการแทรก
  
        // 2. Insert into auction table
        const auctionSql = `
          INSERT INTO auctions
          (car_ID, auction_start_date, auction_end_date, auction_start_time, auction_end_time,
          auction_status, auction_starting_price, auction_minimum_price, auction_current_price)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const auctionValues = [
          car_ID, newCar.auction_start_date, newCar.auction_end_date, newCar.auction_start_time,
          newCar.auction_end_time, newCar.auction_status, newCar.auction_starting_price,
          newCar.auction_minimum_price, newCar.auction_current_price
        ];
  
        db.query(auctionSql, auctionValues, (err, auctionResult) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).send('Error inserting auction data');
            });
          }
  
          // 3. Insert into bids table
          const bidsSql = `
            INSERT INTO bids
            (car_ID, current_bid, bid_increment)
            VALUES (?, ?, ?)
          `;
          const bidsValues = [
            car_ID, newCar.current_bid, newCar.bid_increment
          ];
  
          db.query(bidsSql, bidsValues, (err, bidsResult) => {
            if (err) {
              return db.rollback(() => {
                res.status(500).send('Error inserting bids data');
              });
            }
  
            // 4. Insert into favorites table
            const favSql = `
              INSERT INTO favorites
              (car_ID)
              VALUES (?)
            `;
            const favValues = [car_ID];
  
            db.query(favSql, favValues, (err, favResult) => {
              if (err) {
                console.error('Error inserting favorites data:', err);
                return db.rollback(() => {
                  res.status(500).send('Error inserting favorites data');
                });
              }
  
              // Commit การทำธุรกรรมทั้งหมด
              db.commit(err => {
                if (err) {
                  return db.rollback(() => {
                    res.status(500).send('Transaction commit failed');
                  });
                }
  
                // ส่งการตอบกลับเมื่อการทำธุรกรรมเสร็จสมบูรณ์
                res.send('Car, auction, bids, and favorites data added successfully');
              });
            });
          });
        });
      });
    });
  });
  
  
// api page adminpanel
app.delete('/api/deleteCar/:carID', (req, res) => {
    const { carID } = req.params;
  
    const query = 'DELETE FROM car WHERE car_ID = ?';
  
    db.execute(query, [carID], (err, result) => {
      if (err) {
        console.error('Error deleting car:', err);
        return res.status(500).json({ message: 'Failed to delete car' });
      }
  
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Car not found' });
      }
  
      return res.status(200).json({ message: 'Car deleted successfully' });
    });
  });

//api page adminpanel
app.delete('/api/deleteusers/:userID', (req, res) => {
    const { userID } = req.params;
  
    const deleteQuery = 'DELETE FROM users WHERE Userid = ?';
    db.query(deleteQuery, [userID], (err, result) => {
      if (err) {
        console.error('Error deleting user:', err);
        return res.status(500).json({ error: 'Failed to delete user' });
      }
  
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      res.status(200).json({ message: 'User deleted successfully' });
    });
  });

//api page Home
app.post('/favorites', (req, res) => {
    const { car_ID, userID } = req.body;  // ดึง userID จาก body
    // console.log("favorite",car_ID ,userID);

    // ตรวจสอบว่ามีการกด favorite หรือไม่สำหรับ user นี้
    db.query('SELECT * FROM favorites WHERE userID = ? AND car_ID = ?', [userID, car_ID], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error querying favorites' });

        if (results.length > 0) {
            // หากพบว่ามี car_ID อยู่ใน favorites แล้ว (ลบออก)
            const currentStatus = results[0].status; // ดึง status ปัจจุบัน

            if (currentStatus === 1) {
                // ถ้าเป็น favorite อยู่แล้ว (status = 1) ให้ลบ favorite
                db.query('UPDATE favorites SET status = 0 WHERE userID = ? AND car_ID = ?', [userID, car_ID], (err) => {
                    if (err) return res.status(500).json({ error: 'Error removing favorite' });

                    // ลด rating ของรถ
                    updateCarRating(car_ID, -1);  // ลด rating ลง 1 เมื่อลบ favorite
                    res.json({ success: true, message: 'Favorite removed and rating updated', favorite_status: false });
                });
            } else {
                // ถ้าไม่ได้ favorite (status = 0) ให้เพิ่มกลับ
                db.query('UPDATE favorites SET status = 1 WHERE userID = ? AND car_ID = ?', [userID, car_ID], (err) => {
                    if (err) return res.status(500).json({ error: 'Error updating favorite' });

                    // เพิ่ม rating ของรถ
                    updateCarRating(car_ID, 1);  // เพิ่ม rating ขึ้น 1 เมื่อเพิ่ม favorite
                    res.json({ success: true, message: 'Favorite added and rating updated', favorite_status: true });
                });
            }
        } else {
            // ถ้ายังไม่มีการ favorite สำหรับ user นี้ เพิ่ม car_ID เข้าไปใน favorites
            db.query('INSERT INTO favorites (userID, car_ID, status) VALUES (?, ?, 1)', [userID, car_ID], (err) => {
                if (err) return res.status(500).json({ error: 'Error adding favorite' });

                // เพิ่ม rating ของรถ
                updateCarRating(car_ID, 1);  // เพิ่ม rating ขึ้น 1 เมื่อเพิ่ม favorite
                res.json({ success: true, message: 'Favorite added and rating updated', favorite_status: true });
            });
        }
    });
});

//api page Home
const updateCarRating = (car_ID, change) => {
    const query = 'UPDATE car SET car_rating = car_rating + ? WHERE car_ID = ?';
    db.query(query, [change, car_ID], (err, result) => {
        if (err) {
            console.error('Error updating car rating:', err);
        } else {
            console.log('Car rating updated successfully');
        }
    });
};

//api page Home
app.post('/favorites/status', (req, res) => {
    const { car_ID, userID } = req.body;

    if (!car_ID) {
        return res.status(400).json({ error: 'ต้องระบุ car_ID' });
    }

    db.query('SELECT * FROM favorites WHERE userID = ? AND car_ID = ? AND status = 1', [userID, car_ID], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'เกิดข้อผิดพลาดในการตรวจสอบสถานะรายการโปรด' });
        }

        // ถ้าพบผลลัพธ์ แสดงว่า car_ID นี้เป็นรายการโปรดของผู้ใช้
        const isFavorite = results.length > 0;
        res.json({ favorite_status: isFavorite });
    });
});

//api page Home
app.post('/cars', (req, res) => {
    const query = 'SELECT car.*, bids.*, auctions.* FROM car LEFT JOIN bids ON car.car_ID = bids.car_ID LEFT JOIN auctions ON car.car_ID = auctions.car_ID'; 
    
    db.query(query, (err, results) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูล:', err);
        return res.status(500).send('Server error');
      }
      res.json(results);  // ส่งข้อมูลเป็น JSON ไปยังฝั่ง Frontend
    });
});

// Api Page show favorite page
app.post('/showfavorite', (req, res) => {
    const { userID } = req.body; // รับ userID จาก body
    if (!userID) {
      return res.status(400).json({ error: 'userID is required' });
    }
    const query = `
      SELECT 
          car.*, 
          favorites.status, 
          bids.*
      FROM 
          favorites
      JOIN 
          car ON favorites.car_ID = car.car_ID
      JOIN 
          bids ON car.car_ID = bids.car_ID
      WHERE 
          favorites.userID = ? 
          AND favorites.status = 1

    `;
  
    db.query(query, [userID], (err, results) => {
      if (err) {
        console.error('Error fetching favorite cars:', err);
        return res.status(500).json({ error: 'Error fetching favorite cars' });
      }
      res.json(results); // ส่งข้อมูลรายการโปรดกลับไป
    });
  });

// Api Page show Today Auction
app.get('/api/Todayauctions', (req, res) => {
    const query = `
        SELECT auctions.*, 
            car.*, 
            DATE_FORMAT(auctions.auction_start_date, '%d %M %Y') AS formatted_auction_start_date,
            DATE_FORMAT(auctions.auction_end_date, '%d %M %Y') AS formatted_auction_end_date,
            DATE_FORMAT(auctions.auction_start_time, '%h:%i %p') AS formatted_auction_start_time,  
            DATE_FORMAT(auctions.auction_end_time, '%h:%i %p') AS formatted_auction_end_time 
        FROM auctions
        JOIN car ON auctions.car_ID = car.car_ID

    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching auctions:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        
        // console.log('Auction results:', results);  
        if (results.length === 0) {
            return res.status(404).json({ message: 'No active auctions found' });
        }

        res.json(results);
    });
});

// API Page Today Search
app.get('/api/TodaySearch', (req, res) => {
    let { searchTerm } = req.query;
    console.log(searchTerm);

    // สร้าง query SQL พื้นฐาน
    let query = `
      SELECT auctions.*, 
             car.*,
                DATE_FORMAT(auctions.auction_start_date, '%d %M %Y') AS formatted_auction_start_date,
                DATE_FORMAT(auctions.auction_end_date, '%d %M %Y') AS formatted_auction_end_date,
                DATE_FORMAT(auctions.auction_start_time, '%h:%i %p') AS formatted_auction_start_time,  
                DATE_FORMAT(auctions.auction_end_time, '%h:%i %p') AS formatted_auction_end_time  
      FROM auctions
      JOIN car ON auctions.car_ID = car.car_ID
      WHERE 
        CURDATE() BETWEEN auctions.auction_start_date AND auctions.auction_end_date

    `;

    const queryParams = [];

    if (searchTerm) {
        searchTerm = searchTerm.toLowerCase();
        
        query += ` AND (LOWER(car.car_brand) LIKE ? OR LOWER(car.car_model) LIKE ? OR LOWER(car.car_details) LIKE ?`;
        queryParams.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`);

        query += `)`;
    }

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching auctions:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        console.log('Auction results:', results);
        if (results.length === 0) {
            return res.status(404).json({ message: 'No active auctions found' });
        }

        // ส่งผลลัพธ์การค้นหากลับไป
        res.json(results);
    });
});

// api page celendar
app.get('/api/calendar', (req, res) => {

    const query = `
        SELECT 
        auctions.*, 
        car.*, 
        DATE_FORMAT(auctions.auction_start_date, '%d %M %Y') AS formatted_auction_start_date,
        DATE_FORMAT(auctions.auction_end_date, '%d %M %Y') AS formatted_auction_end_date,
        DATE_FORMAT(auctions.auction_start_time, '%h:%i %p') AS formatted_auction_start_time,  
        DATE_FORMAT(auctions.auction_end_time, '%h:%i %p') AS formatted_auction_end_time  
        FROM auctions
        JOIN car ON auctions.car_ID = car.car_ID;
    `;
    
    db.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching data: ', err);
        return res.status(500).send('Internal Server Error');
      }
  
      // Send response with auction data
      res.json(results);
    });
  });

  app.get('/api/othersearch', (req, res) => {
    let { searchTerm } = req.query;

    // สร้าง query SQL พื้นฐาน
    let query = `
        SELECT auctions.*, 
            car.*,
        DATE_FORMAT(auctions.auction_start_date, '%d %M %Y') AS formatted_auction_start_date,
        DATE_FORMAT(auctions.auction_end_date, '%d %M %Y') AS formatted_auction_end_date,
        DATE_FORMAT(auctions.auction_start_time, '%h:%i %p') AS formatted_auction_start_time,  
        DATE_FORMAT(auctions.auction_end_time, '%h:%i %p') AS formatted_auction_end_time  
        FROM auctions
        JOIN car ON auctions.car_ID = car.car_ID
    `;

    const queryParams = [];

    if (searchTerm) {
        searchTerm = searchTerm.toLowerCase();
        
        query += ` AND (LOWER(car.car_brand) LIKE ? OR LOWER(car.car_model) LIKE ? OR LOWER(car.car_details) LIKE ?`;
        queryParams.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`);

        query += `)`;
    }

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching auctions:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        console.log('Auction results:', results);
        if (results.length === 0) {
            return res.status(404).json({ message: 'No active auctions found' });
        }

        // ส่งผลลัพธ์การค้นหากลับไป
        res.json(results);
    });
});

//api page detail
  app.get("/api/detail/:carID", (req, res) => {
    const { carID } = req.params;  

    const query = `
            SELECT a.*, c.*, b.*, h.*
            FROM auctions a
            INNER JOIN car c ON a.car_ID = c.car_ID
            LEFT JOIN bids b ON a.car_ID = b.car_ID 
            LEFT JOIN bid_history h ON b.bid_id = h.bid_id
            WHERE a.car_ID = ?;  
    `;
  
    // ดึงข้อมูลจากฐานข้อมูล
    db.query(query, [carID], (err, results) => {
      if (err) {
        console.error("เกิดข้อผิดพลาดในการดึงข้อมูล:", err);
        return res.status(500).json({ message: "ไม่สามารถดึงข้อมูลได้" });
      }
  
      // ตรวจสอบว่าพบข้อมูลหรือไม่
      if (results.length === 0) {
        return res.status(404).json({ message: "ไม่พบข้อมูลรถนี้" });
      }
  
      // ส่งข้อมูลรถกลับไปยัง frontend
      res.json(results[0]);
    });
  });

// api page detail 
app.get('/api/bidhistory/:carID', (req, res) => {
    const { carID } = req.params
  
    if (!carID) {
      return res.status(400).send('carID is required.');
    }
  
    // SQL query modified to include car_ID in the results
    const query = `
    SELECT bh.*, u.Username 
    FROM bid_history bh
    JOIN users u ON bh.UserID = u.UserID
    WHERE bh.car_ID = ?;
    `;
  
    db.query(query, [carID], (err, results) => {
      if (err) {
        console.error('Error querying bid history:', err);
        res.status(500).send('An error occurred while querying the bid history.');
        return;
      }
  
      // Respond with the query results
      res.json(results);
    });
  });

// api page detail 
app.post('/api/bid', (req, res) => {
    const { carID, userID, bidAmount } = req.body;
  
    if (!carID || !userID || bidAmount === undefined) {
      return res.status(400).send('Missing carID, userID, or bidAmount.');
    }
  
    const selectQuery = 'SELECT current_bid, bid_increment FROM bids WHERE car_ID = ?';
    db.query(selectQuery, [carID], (err, results) => {
      if (err) {
        console.error('Error fetching current bid:', err);
        return res.status(500).send('An error occurred while fetching the current bid.');
      }
  
      const currentBid = results[0] ? results[0].current_bid : 0;
      const bidIncrement = results[0] ? results[0].bid_increment : 0;
  
      // Check if bidAmount is greater than current_bid and bid_increment
      if (bidAmount <= currentBid) {
        console.log("Bid must be higher than the current bid. Current Bid:", currentBid);
        return res.status(400).send(`Bid must be higher than the current bid. Current Bid: ${currentBid}`);
      }
  
      if (bidAmount <= bidIncrement) {
        console.log(`Bid must be higher than the current bid plus bid increment of ${bidIncrement}`);
        return res.status(400).send(`Bid must be higher than the current bid plus bid increment of ${bidIncrement}`);
      }
  
      db.beginTransaction(err => {
        if (err) {
          console.error('Transaction error:', err);
          return res.status(500).send('An error occurred while starting the transaction.');
        }
  
        const insertQuery = `
          INSERT INTO bid_history (car_ID, UserID, bid_amount, bid_time)
          VALUES (?, ?, ?, NOW());
        `;
  
        db.query(insertQuery, [carID, userID, bidAmount], (err, result) => {
          if (err) {
            return db.rollback(() => {
              console.error('Error inserting bid:', err);
              return res.status(500).send('An error occurred while submitting the bid.');
            });
          }
  
          const updateBidsQuery = `
            UPDATE bids
            SET current_bid = ?
            WHERE car_ID = ?;
          `;
  
          db.query(updateBidsQuery, [bidAmount, carID], (err, result) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error updating current bid:', err);
                return res.status(500).send('An error occurred while updating the current bid.');
              });
            }
  
            const updateAuctionQuery = `
              UPDATE auctions
              SET auction_current_price = ?
              WHERE car_ID = ?;
            `;
  
            db.query(updateAuctionQuery, [bidAmount, carID], (err, result) => {
              if (err) {
                return db.rollback(() => {
                  console.error('Error updating auction current price:', err);
                  return res.status(500).send('An error occurred while updating the auction current price.');
                });
              }
  
              db.commit(err => {
                if (err) {
                  return db.rollback(() => {
                    console.error('Error committing transaction:', err);
                    return res.status(500).send('An error occurred while committing the transaction.');
                  });
                }
  
                res.status(201).send('Bid submitted and auction updated successfully!');
              });
            });
          });
        });
      });
    });
  });
  
  

// Api page detail 
app.post('/api/completeAuction', (req, res) => {
    const { carID, userID } = req.body;
    console.log(carID,userID);
  
    const query = `
      SELECT UserID, bid_amount
      FROM bid_history
      WHERE car_id = ?
      ORDER BY bid_amount DESC
      LIMIT 1
    `;
  
    db.query(query, [carID], (error, results) => {
      if (error) {
        console.error("Error querying the database:", error);
        return res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการเข้าถึงฐานข้อมูล" });
      }
  
      if (results.length === 0) {
        return res.json({ success: false, message: "ยังไม่มีการประมูลสำหรับรถคันนี้" });
      }
  
      const highestBidder = results[0];
  
      if (highestBidder.UserID === userID) {
        // ผู้ใช้เป็นผู้ประมูลสูงสุด
        return res.json({ success: true, message: "ยินดีด้วยคุณคือผู้ประมูลสูงสุด" });
      } else {
        // ผู้ใช้ไม่ใช่ผู้ประมูลสูงสุด
        return res.json({ success: false, message: "คุณไม่ใช่ผู้ประมูลสูงสุดสำหรับการประมูลนี้" });
      }
    });
  });


  // **ดึงข้อมูลผู้ใช้ตาม UserID**
app.get("/api/user/:id", (req, res) => {
    const { id } = req.params;
    db.query(
      "SELECT UserID, firstname, lastname, Username, email FROM users WHERE UserID = ?", 
      [id], 
      (err, results) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ error: "Database error occurred" });
        }
  
        if (results.length === 0) {
          return res.status(404).json({ error: "User not found" });
        }
  
        const user = results[0];
        res.status(200).json(user); // ส่งข้อมูลกลับไป
      }
    );
  });
  
  
  // **อัปเดตการเปลี่ยนรหัสผ่าน**
app.post("/api/user/userupdate", async (req, res) => {
    const { firstName, lastName, Username, currentPassword, newPassword, UserID, email } = req.body;
  
    if (!UserID || (!firstName && !lastName && !Username && !newPassword && !email)) {
      return res.status(400).json({ error: "Please provide required fields" });
    }
  
    try {
      db.query("SELECT * FROM users WHERE UserID = ?", [UserID], async (err, results) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ error: "Database error occurred" });
        }
  
        if (results.length === 0) {
          return res.status(404).json({ error: "User not found" });
        }
  
        const user = results[0];
  
        // ตรวจสอบ Current Password
        if (currentPassword) {
          const isPasswordCorrect = await bcrypt.compare(currentPassword + "1234", user.password);
          if (!isPasswordCorrect) {
            return res.status(400).json({ error: "Current password is incorrect" });
          }
        }
  
        // เตรียมข้อมูลอัปเดต
        const updates = {};
        if (firstName) updates.firstname = firstName;
        if (lastName) updates.lastname = lastName;
        if (Username) updates.Username = Username;
        if (email) updates.email = email;
  
        // เปลี่ยนรหัสผ่านหากมีการใส่ newPassword
        if (newPassword) {
          const saltRounds = 10;
          updates.password = await bcrypt.hash(newPassword + "1234", saltRounds);
        }
  
        // เตรียมคำสั่ง SQL สำหรับอัปเดต
        const updateFields = Object.keys(updates).map((key) => `${key} = ?`).join(", ");
        const updateValues = Object.values(updates);
  
        db.query(
          `UPDATE users SET ${updateFields} WHERE UserID = ?`,
          [...updateValues, UserID],
          (err) => {
            if (err) {
              console.error("Update error:", err);
              return res.status(500).json({ error: "Failed to update user" });
            }
  
            // ดึงข้อมูลที่อัปเดตแล้วกลับมา
            db.query("SELECT UserID, firstname, lastname, Username, email FROM users WHERE UserID = ?", [UserID], (err, results) => {
              if (err) {
                console.error("Error fetching updated user data:", err);
                return res.status(500).json({ error: "Failed to fetch updated user data" });
              }
  
              const updatedUser = results[0];
              return res.status(200).json({
                message: "Profile updated successfully",
                user: updatedUser,
              });
            });
          }
        );
      });
    } catch (error) {
      console.error("Unexpected error:", error);
      return res.status(500).json({ error: "An unexpected error occurred" });
    }
  });
  
  // **ดึง Username ตาม UserID**
app.get("/api/get-username", (req, res) => {
    const { car_id, user_id } = req.query;
    console.log("UserID:", user_id, "CarID:", car_id);
    
    // SQL Query ที่ดึงข้อมูลจากทั้งตาราง users และ cars
    const query = `
        SELECT 
            auctions.*, 
            car.*, 
            bid_history.*, 
            users.*
        FROM 
            auctions
        JOIN 
            car ON auctions.car_ID = car.car_ID
        JOIN 
            bid_history ON bid_history.car_ID = car.car_ID
        JOIN 
            users ON bid_history.UserID = users.UserID
        WHERE 
            bid_history.UserID = ? 
            AND car.car_ID = ?
    `;
    
    db.query(query, [user_id, car_id], (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error occurred" });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ error: "User or car not found" });
      }
  
      res.status(200).json(results[0]);
    });
  });

  app.get("/api/auction-details", (req, res) => {
    const { car_id, user_id } = req.query;
  
    // Ensure both car_id and user_id are provided
    if (!car_id || !user_id) {
      return res.status(400).json({ error: "car_id and user_id are required" });
    }
  
    // Construct the SQL query
    const query = `
        SELECT 
            auctions.*, 
            car.*, 
            bid_history.*, 
            users.*,
            DATE_FORMAT(auctions.auction_start_date, '%d %M %Y') AS formatted_auction_start_date,
            DATE_FORMAT(auctions.auction_end_date, '%d %M %Y') AS formatted_auction_end_date,
            DATE_FORMAT(auctions.auction_start_time, '%h:%i %p') AS formatted_auction_start_time,  
            DATE_FORMAT(auctions.auction_end_time, '%h:%i %p') AS formatted_auction_end_time  
        FROM 
            auctions
        JOIN 
            car ON auctions.car_ID = car.car_ID
        JOIN 
            bid_history ON bid_history.car_ID = car.car_ID
        JOIN 
            users ON bid_history.UserID = users.UserID
        WHERE 
            bid_history.UserID = ? 
            AND car.car_ID = ?;

    `;
  
    // Execute the query
    db.query(query, [user_id, car_id], (err, results) => {
      if (err) {
        console.error("Error fetching auction data:", err);
        return res.status(500).json({ error: "Failed to fetch auction data" });
      }
      res.json(results); // Send the filtered results
    });
  });
  
  

  app.post("/api/submit-comment", (req, res) => {
    const { car_id, date, comment, rating} = req.body;

    const query = `
      INSERT INTO review 
        (car_ID, review_rating, review_comment, review_date)
      VALUES
        (?, ?, ?, ?)
    `;
  
    db.query(query, [car_id, rating, comment, date], (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error occurred" });
      }
  
      // ส่งข้อมูลกลับไปที่ Frontend พร้อมกับ ID ของ review ที่ถูกเพิ่ม
      res.status(200).json({ message: "Review submitted successfully", reviewId: results.insertId });
    });
  });
  

// Route: ดึงข้อมูลรีวิว
app.get("/api/reviews", (req, res) => {
  const sql = `
    SELECT 
        r.review_ID,
        r.car_ID,
        r.review_rating,
        r.review_comment,
        r.review_date,
        u.Username,
        c.car_brand,
        c.car_model,
        c.car_year
    FROM 
        review r
    JOIN 
        bid_history bh ON r.car_ID = bh.car_ID
    JOIN 
        users u ON bh.UserID = u.UserID
    JOIN 
        car c ON r.car_ID = c.car_ID
    WHERE 
        bh.bid_amount = (
            SELECT 
                MAX(bid_amount)
            FROM 
                bid_history
            WHERE 
                car_ID = r.car_ID
        );
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to retrieve reviews" });
    }
    res.json(result);
  });
});

  


const port = 9500;

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
