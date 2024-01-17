const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const uri = "mongodb+srv://ammarpauzan:Mar25052002@cluster0.nyml2l7.mongodb.net/?retryWrites=true&w=majority";
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const saltRounds = 10;
const swaggerJsdoc = require('swagger-jsdoc');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'VMS API',
      version: '1.0.0',
    },
  components: {  // Add 'components' section
      securitySchemes: {  // Define 'securitySchemes'
          bearerAuth: {  // Define 'bearerAuth'
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
          }
      }
    }
  },
  apis: ['./index.js'], // Replace this with the file containing your route definitions
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
// Create a map to store banned users with their roles
const bannedUsers = new Map();

// Function to create a user-specific rate limiter
function createUserRateLimiter(windowMs, maxAttempts) {
  return rateLimit({
    windowMs,
    max: maxAttempts,
    message: (req, res) => { // Check if the user is banned and calculate the time left
    const bannedUserKey = `${req.body.username}_${req.body.role}`;
    if (bannedUsers.has(bannedUserKey)) {
      const timeLeft = bannedUsers.get(bannedUserKey) - Date.now();
      const minutesLeft = Math.ceil(timeLeft / (60 * 1000));
      return `Too many login attempts. Please try again in ${minutesLeft} minutes.`;
    } else {
      return 'Too many login attempts. Please try again later.';
    }},
    keyGenerator: (req) => {
      // Generate a unique key based on username and role
      return `${req.body.username}_${req.body.role}`;
    },
    onLimitReached: (req) => {
      // Add the banned user to the map with the expiration time
      const expirationTime = Date.now() + windowMs;
      bannedUsers.set(`${req.body.username}_${req.body.role}`, expirationTime);

      // Remove the user from the map after the ban duration
      setTimeout(() => {
        bannedUsers.delete(`${req.body.username}_${req.body.role}`);
      }, windowMs);
    },
  });
}

// Example rate limiters for different roles
const bossLoginLimiter = createUserRateLimiter(5 * 60 * 1000, 3); // 5 minutes, 3 attempts
const adminLoginLimiter = createUserRateLimiter(5 * 60 * 1000, 3); // 5 minutes, 3 attempts
const securityLoginLimiter = createUserRateLimiter(5 * 60 * 1000, 3); // 5 minutes, 3 attempts

// Connect the client to the server (optional starting in v4.7)
async function run() {
    try {
      // Connect the client to the server  (optional starting in v4.7)
      await client.connect();
      // Send a ping to confirm a successful connection
      await client.db("admin").command({ ping: 1 });
      console.log("Pinged your deployment. You successfully connected to MongoDB!");
    app.use(express.json());
    app.listen(port, () => {
      console.log(`Server listening at http://localhost:${port}`);
    });


    app.get('/', (req, res) => {
       res.send('Welcome To Visitor Management')
    });

/**
 *  @swagger
 * /regBoss:
 *   post:
 *     summary: Register an Admin
 *     description: Registers an Admin if not already registered
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Boss
 */
app.post('/regBoss', async (req, res) => {
  let data = req.body;
  res.send(await regBoss(client, data));
});

/**
* @swagger
* /BossLogin:
*   post:
*     summary: Boss Login
*     description: Authenticates a Boss's login credentials
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*               password:
*                 type: string
*     responses:
*       '401':
*         description: Invalid username or password
*       '404':
*         description: User not found
*       '500':
*         description: Internal server error
*     tags:
*       - Boss
*/
app.post('/BossLogin',bossLoginLimiter, async (req, res) => {
  let data = req.body;
  res.send(await Bosslogin(client, data));
});
/** 
 *  @swagger
 * /Bossread:
 *   get:
 *     summary: Retrieve data based on user role
 *     description: Retrieves data based on the user's role (Boss,Admin, Security, or Visitor)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Boss
 */
app.get('/BossRead', authenticateToken, async (req, res) => {
  let data = req.user;
  res.send(await read(client, data));
});

/**
* @swagger
* /DeleteUser:
*   delete:
*     summary: Delete Admin or Security User
*     description: Deletes an Admin or Security user (Boss access only)
*     security:
*       - bearerAuth: []
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*                 description: Username of the user to delete
*               role:
*                 type: string
*                 description: Role of the user to delete (Admin or Security)
*     responses:
*       '401':
*         description: Unauthorized or Invalid token
*       '403':
*         description: Forbidden access
*       '404':
*         description: User not found
*       '500':
*         description: Internal server error
*     tags:
*       - Boss
*/
app.delete('/DeleteUser', authenticateToken, async (req, res) => {
  const data = req.user;
  const { username, role } = req.body;

  // Check if the requester is the Boss
  if (data.role !== 'Boss') {
    return res.status(403).send('Forbidden access');
  }

  // Ensure Boss cannot delete their own account
  if (data.username === username && data.role === role) {
    return res.status(403).send('Cannot delete own account');
  }

  const deletionResult = await deleteUser(client, username, role);

  if (deletionResult.success) {
    return res.send(deletionResult.message);
  } else {
    return res.status(500).send(deletionResult.message);
  }
});


/**
 *  @swagger
 * /regAdmin:
 *   post:
 *     summary: Register an Admin
 *     description: Registers an Admin if not already registered
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Boss
 */
    app.post('/regAdmin', authenticateToken, async (req, res) => {
      let data = req.user;
      let DataVis = req.body;
      res.send(await regAdmin(client, data, DataVis));
    });

    /**
 * @swagger
 * /Adminlogin:
 *   post:
 *     summary: Admin Login
 *     description: Authenticates a user's login credentials
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Invalid username or password
 *       '404':
 *         description: User not found
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Admin
 */
    app.post('/Adminlogin', adminLoginLimiter,async (req, res) => {
      let data = req.body;
      res.send(await Adminlogin(client, data));
    });

/** 
 *  @swagger
 * /Adminread:
 *   get:
 *     summary: Retrieve data based on user role
 *     description: Retrieves data based on the user's role (Admin, Security, or Visitor)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Admin
 */
app.get('/AdminRead', authenticateToken, async (req, res) => {
  let data = req.user;
  res.send(await read(client, data));
});

 /**
 * @swagger
 * /Securitylogin:
 *   post:
 *     summary: Security Login
 *     description: Authenticates a user's login credentials
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Invalid username or password
 *       '404':
 *         description: User not found
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Security
 */
  app.post('/Securitylogin',securityLoginLimiter, async (req, res) => {
    let data = req.body;
    res.send(await Securitylogin(client, data));
  });
 
/**
 * @swagger
 * /Securityregister:
 *   post:
 *     summary: Register a user
 *     description: Registers a user based on role (Admin or Security)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '409':
 *         description: Username already in use
 *       '403':
 *         description: Not allowed to register
 *     tags:
 *       - Admin
 */

    app.post('/Securityregister', authenticateToken, async (req, res) => {
      let data = req.user;
      let DataVis = req.body;
      res.send(await register(client, data, DataVis));
    });
/**
 * @swagger
 * /test/Securityregister:
 *   post:
 *     summary: Register a user
 *     description: Registers a user based on role (Admin or Security)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '409':
 *         description: Username already in use
 *       '403':
 *         description: Not allowed to register
 *     tags:
 *       - Admin
 */

app.post('/test/Securityregister', async (req, res) => {
  let data = req.user;
  let DataVis = req.body;
  res.send(await testregister(client,DataVis));
});

/**
 * @swagger
 * /Visitorregister:
 *   post:
 *     summary: Register a user
 *     description: Registers a user based on role (Admin or Security)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               vehicleNo:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '409':
 *         description: Username already in use
 *       '403':
 *         description: Not allowed to register
 *     tags:
 *       - Security
 */

    app.post('/Visitorregister', authenticateToken, async (req, res) => {
      let data = req.user;
      let DataVis = req.body;
      res.send(await Securityregister(client, data, DataVis));
    });

/** 
 *  @swagger
 * /Securityread:
 *   get:
 *     summary: Retrieve data based on user role
 *     description: Retrieves data based on the user's role (Admin, Security, or Visitor)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Security
 */
    app.get('/SecurityRead', authenticateToken, async (req, res) => {
      let data = req.user;
      res.send(await read(client, data));
    });
/**
 * @swagger
 * /DeleteVisitor:
 *   delete:
 *     summary: Delete Visitor
 *     description: Deletes a Visitor (Security access only)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               passvisitor:
 *                 type: string
 *                 description: Visitor Pass to delete the Visitor
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '403':
 *         description: Forbidden access or Visitor not created by the Security
 *       '404':
 *         description: Visitor pass not found or Visitor not found
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Security
 */
app.delete('/DeleteVisitor', authenticateToken, async (req, res) => {
  const data = req.user;
  const visitorPass = req.body.passvisitor;

  try {
    // Check if the requester is a Security user
    if (data.role !== 'Security') {
      return res.status(403).send('Forbidden access');
    }

    // Find the visitor by passvisitor
    const visitor = await client
      .db('Database')
      .collection('PassVisitor')
      .findOne({ passvisitor: visitorPass });

    if (!visitor) {
      return res.status(404).send('Visitor pass not found');
    }

    // Check if the requester is the same security user who created the visitor
    if (visitor.security !== data.username) {
      return res.status(403).send('Forbidden access: Visitor not created by the Security');
    }

    // Proceed with deleting the visitor
    const deletionResult = await client
      .db('Database')
      .collection('PassVisitor')
      .deleteOne({ passvisitor: visitorPass });

    if (deletionResult.deletedCount > 0) {
      return res.send(`Visitor with pass ${visitorPass} successfully deleted`);
    } else {
      return res.status(500).send('Error deleting visitor');
    }
  } catch (error) {
    console.error('Error deleting visitor:', error);
    return res.status(500).send('Internal server error');
  }
});


/**
 * @swagger
 * /RetrieveSecurityNumber:
 *   post:
 *     summary: Retrieve Security Phone Number by Visitor Pass
 *     description: Retrieves the Security Phone Number using the Visitor Pass (Admin access only)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               passvisitor:
 *                 type: string
 *                 description: Visitor Pass to retrieve Security Phone Number
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '403':
 *         description: Forbidden access
 *       '404':
 *         description: Visitor pass not found or Security not found
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Admin
 */
    app.post('/RetrieveSecurityNumber',authenticateToken,async (req,res) =>{
      let data =req.user;
      let visitorPass = req.body;
      res.send(await getSecurityPhoneByVisitorPass(client, data, visitorPass))
    });
    /**
 * @swagger
 * /RetrieveVisitorPass:
 *   post:
 *     summary: Retrieve Visitor Pass by Visitor ID
 *     description: Retrieves the Visitor Pass using the Visitor ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               VisitorID:
 *                 type: string
 *                 description: Visitor ID to retrieve Visitor Pass
 *     responses:
 *       '403':
 *         description: Forbidden access
 *       '404':
 *         description: Visitor ID not found 
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Visitor
 */
    app.post('/RetrieveVisitorPass',async (req,res) =>{
      let visitorPass = req.body;
      res.send(await getVisPassByVisID(client,visitorPass))
    });
    
} catch (e) {
    console.error(e);

  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.error);
// Function to encrypt password with strength validation
async function encryptPassword(password) {
  // Check if password meets strength requirements

  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}
  async function decryptPassword(password, compare) {
      const match = await bcrypt.compare(password, compare)
      return match;
    
    }
    function generateToken(user){
      return jwt.sign(
      user,    //this is an obj
      'mypassword',           //password
      { expiresIn: '1h' });  //expires after 1 hour
    }
    function authenticateToken(req, res, next) {
      let header = req.headers.authorization;
    
      if (!header) {
        return res.status(401).send('Unauthorized');
      }
    
      let token = header.split(' ')[1];
    
      jwt.verify(token, 'mypassword', function(err, decoded) {
        if (err) {
          console.error(err);
          return res.status(401).send('Invalid token');
        }
    
        req.user = decoded;
        next();
      });
    }
    function generateVisitorPassIdentifier() {
      const length = 10; // Length of the identifier
      const charset = "abcdefghijklmnopqrstuvmxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"; // Characters to include in the identifier
      let identifier = "";
    
      for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        identifier += charset[randomIndex];
      }
      return identifier;
    }

    
    // Function to delete an admin or security user
async function deleteUser(client, username, role) {
  try {
    const userToDelete = await client
      .db('Database')
      .collection(role === 'Admin' ? 'Admin1' : 'Security')
      .findOne({ username });

    if (!userToDelete) {
      return { success: false, message: 'User not found' };
    }

    // Additional checks or operations before deletion if needed...

    const deletionResult = await client
      .db('Database')
      .collection(role === 'Admin' ? 'Admin1' : 'Security')
      .deleteOne({ username });

    if (deletionResult.deletedCount > 0) {
      return { success: true, message: `User '${username}' (${role}) successfully deleted` };
    } else {
      return { success: false, message: 'Error deleting user' };
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    return { success: false, message: 'Internal server error' };
  }
}
    async function regBoss(client, data) {
      const existingAdmin = await client
        .db("Database")
        .collection("Boss")
        .findOne({ username: data.username });
    
      if (existingAdmin) {
        return "Boss already registered";
      }else {
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        // Check if password meets strength requirements
        if (!passwordRegex.test(data.password)) {
          throw new Error('Password must contain at least 8 characters, including at least one uppercase letter, one lowercase letter, one digit, and one special character.');
        }else{
        data.password = await encryptPassword(data.password);
        data.role = "Boss";
        const result = await client.db("Database").collection("Boss").insertOne(data);
        return 'Boss registered';
        }
      }
        }
  
         //login 
    async function Bosslogin(client, data) {
      const user = await client.db('Database').collection('Boss').findOne({ username: data.username });
      if (user) {
        const isPasswordMatch = await decryptPassword(data.password, user.password);
    
        if (isPasswordMatch) {
          {
            return Display(user.role) +" Token for " + user.role + ": " + generateToken(user);
            }
        } else {
          return "Wrong password";
        }
      } else {
        return "User not found";
      }
    }  
    
    //register admin 
    async function regAdmin(client, data, DataVis) {

      temporary = await client.db('Database').collection('Admin1').findOne({ username:DataVis.username})
    if(!temporary) {
      if (data.role === 'Boss') {
        DataVis.password = await encryptPassword(DavaVis.password);
        DataVis.role = "Admin";
        const result = await client.db("Database").collection("Admin1").insertOne(DataVis);
        return 'Admin registered successfully';}
      else {
            return'Only Boss have the authorize to register!!!';
            }
        
      }else{
        return "Only one admin can be register";}
    }
 
       //login 
  async function Adminlogin(client, data) {
    const user = await client.db('Database').collection('Admin1').findOne({ username: data.username });
    if (user) {
      const isPasswordMatch = await decryptPassword(data.password, user.password);
  
      if (isPasswordMatch) {
        
        return Display(user.role) +" Token for " + user.role + ": " + generateToken(user);
        
      } else {
        return "Wrong password";
      }
    } else {
      return "User not found";
    }
  }
   //login 
   async function Securitylogin(client, data) {
    const user = await client
      .db("Database")
      .collection("Security")
      .findOne({ username: data.username });
  
    if (user) {
      const isPasswordMatch = await decryptPassword(data.password, user.password);
  
      if (isPasswordMatch) {
        
        return Display(user.role) + "\n Token for " + user.role +": " + generateToken(user);
        
      } else {
        return "Wrong password";
      }
    } else {
      return "User not found";
    }
  }

    //register function
    async function register(client, data, DataVis) {

      temporary = await client.db('Database').collection('Security').findOne({username: DataVis.username})
    if(!temporary) {
    
      if (data.role === 'Admin') {
        const result = await client.db('Database').collection('Security').insertOne({
          username: DataVis.username,
          password: await encryptPassword(DataVis.password),
          name: DataVis.name,
          email: DataVis.email,
          phone: DataVis.phone,
          role: 'Security',
          visitors: []
        });
        return 'Security registered successfully';
      }else{
        return 'You are not allowed to register';}
    }else{
      return 'Security username already register';
    }}
        //register function
        async function testregister(client, DataVis) {

          temporary = await client.db('Database').collection('Security').findOne({username: DataVis.username})
        if(!temporary) {
        
         {
            const result = await client.db('Database').collection('Security').insertOne({
              username: DataVis.username,
              password: await encryptPassword(DataVis.password),
              name: DataVis.name,
              email: DataVis.email,
              phone: DataVis.phone,
              role: 'Security',
              visitors: []
            });
            return 'Security registered successfully';
          }

        }}

    async function Securityregister(client, data, DataVis) {
      const currentTime = new Date();
      temporary = await client.db('Database').collection('PassVisitor').findOne({passvisitor: DataVis.passvisitor})
    if(!temporary) {
    if (data.role === 'Security') {
      const newVisitorId = generateVisitorId();
      const visitorPassIdentifier = generateVisitorPassIdentifier();
      const result = await client.db('Database').collection('PassVisitor').insertOne({
        name: DataVis.name,
        email: DataVis.email,
        phone: DataVis.phone,
        vehicleNo: DataVis.vehicleNo,
        role: 'Visitor',
        visitorID: newVisitorId,
        security: data.username,
        securityNumber: data.phone,
        passvisitor: visitorPassIdentifier,
        createdAt: currentTime
      });
      const result1 = await client.db('Database').collection('Security').updateOne(
        { username: data.username },
        { $push: { visitors: DataVis.visitorID} }
      );
      var message = 'Visitor registered successfully\n Visitor ID : '+ newVisitorId;
      return message}
     else {
      return 'Username already in use, please enter another username'
    }}else{
      return 'You are not allowed to register';}}

 
  
  //read from token and checking role to display 
  async function read(client, data) {
    if(data.role == 'Boss') {
      Admins = await client.db('Database').collection('Admin1').find({role:"Admin"}).next() //.next to read in object instead of array
      Security = await client.db('Database').collection('Security').find({role:"Security"}).toArray()
      Visitors = await client.db('Database').collection('PassVisitor').find({role:"Visitor"}).toArray()
      return {Admins, Security, Visitors}
      }
    if(data.role == 'Admin') {
      Security = await client.db('Database').collection('Security').find({role:"Security"}).toArray()
      Visitors = await client.db('Database').collection('PassVisitor').find({role:"Visitor"}).toArray()
      return { Security, Visitors}
      }
  
    if (data.role == 'Security') {
      Visitors = await client.db('Database').collection('PassVisitor').find({security: data.username}).toArray()   
      return { Visitors}
      }
  }
  //output 
  function Display(data) {
    if(data == 'Boss') {
      var message = "You are logged in as Boss\n You can Access:\n 1.Register Security\n 2. Read All Users \n 3. Manage Admin and Security\n";
      return message
    } else if(data == 'Admin') {
      var message = "You are logged in as Admin\n You can Access:\n 1.Register Security\n 2. Read All Security and Visitor\n3.Retrieve Security Number From Visitor Pass\n";
      return message
    } else if (data == 'Security') {
      var message="You are logged in as Security\n You can Access:\n 1.Register Visitor\n 2. Read Visitor's Data";
      return message
    } 
  }

  async function getSecurityPhoneByVisitorPass(client, data, visitorPass) {
    try {
      if (data.role !== 'Admin') {
        return 'Unauthorized access'; // Return a message for unauthorized access
      }
      const visitor = await client
        .db('Database')
        .collection('PassVisitor')
        .findOne({ passvisitor: visitorPass.passvisitor });
      if (visitor) {
        const security = await client
          .db('Database')
          .collection('Security')
          .findOne({ username: visitor.security });
        if (security) {
          return "Security Phone Number : " + security.phone +"\nSecurity Username:"+ security.username + "\nTime:"+visitorPass.createdAt; // Return the security phone number
        } else {
          return 'Security not found';
        }
      } else {
        return 'Visitor pass not found';
      }
    } catch (error) {
      console.error('Error retrieving security phone:', error);
      return 'Error retrieving security phone';
    }
  }
       
  async function getVisPassByVisID(client,visitorData) {
    try {
      const visitor = await client
        .db('Database')
        .collection('PassVisitor')
        .findOne({ visitorID: visitorData.VisitorID });
      if (visitor) {
        return `Visitor Pass: ${visitor.passvisitor} `;
      } else {
        return 'Visitor ID not found';
      }
    } catch (error) {
      console.error('Error retrieving visitor pass:', error);
      return 'Error retrieving visitor pass';
    }
  }
  // Function to generate a visitor ID
// Function to generate a visitor ID with "vID" prefix
function generateVisitorId() {
  const prefix = 'vID'; // Prefix for the visitor ID
  const length = 5; // Length of the random part of the visitor ID
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; // Characters to include in the ID
  let randomPart = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    randomPart += charset[randomIndex];
  }

  return prefix + randomPart;
}
