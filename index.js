const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const uri = "mongodb+srv://ammarpauzan:Mar25052002@cluster0.nyml2l7.mongodb.net/?retryWrites=true&w=majority";
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const saltRounds = 10;
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { PublicClientApplication } = require('@azure/msal-node');
const msalConfig = {
  auth: {
      clientId: 'YOUR_CLIENT_ID', // Replace with your Azure AD app's client ID
      authority: 'https://login.microsoftonline.com/YOUR_TENANT_ID', // Replace with your Azure AD tenant ID
  },
  system: {
      loggerOptions: {
          loggerCallback(loglevel, message, containsPii) {
              console.log(message);
          },
          piiLoggingEnabled: false,
          logLevel: 1,
      },
  },
};
const pca = new PublicClientApplication(msalConfig);

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

async function signIn() {
  const authCodeUrlParameters = {
      scopes: ['openid', 'profile', 'User.Read'],
      redirectUri: 'http://localhost', // Replace with your redirect URI
  };

  try {
      const authResponse = await pca.acquireTokenByDeviceCode(authCodeUrlParameters);
      console.log('Access Token:', authResponse.accessToken);

      // Use the access token to call APIs or perform operations
  } catch (error) {
      console.error('Error acquiring token:', error);
  }
}
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
       res.send("Welcome To Visitor ")
    });


/**
 *  @swagger
 * /regAdmin:
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
 *       '200':
 *         description: Admin registered successfully or already exists
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Admin
 */
    app.post('/regAdmin', async (req, res) => {
      let data = req.body;
      res.send(await regAdmin(client, data));
    });

 /**
 * @swagger
 * /login2:
 *   post:
 *     summary: User Login
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
 app.post('/login2', async (req, res) => {
  let data = req.body;
  res.send(await login(client, data));
});
 /**
 * @swagger
 * /login1:
 *   post:
 *     summary: User Login
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
    app.post('/login1', async (req, res) => {
      let data = req.body;
      res.send(await login(client, data));
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

 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin, Security]
 *               ic:
 *                 type: string
 *               phone:
 *                 type: string
 *               vehicleNo:
 *                 type: string
 *               department:
 *                 type: string
 *               company:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User registered successfully
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
 *               role:
 *                 type: string
 *                 enum: [Admin, Security]
 *               ic:
 *                 type: string
 *               phone:
 *                 type: string
 *               vehicleNo:
 *                 type: string
 *               department:
 *                 type: string
 *               company:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User registered successfully
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
 * /read:
 *   get:
 *     summary: Retrieve data based on user role
 *     description: Retrieves data based on the user's role (Admin, Security, or Visitor)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Admins:
 *                   type: array
 *                   items:
 *                     type: object
 *                 Security:
 *                   type: object
 *                 Visitors:
 *                   type: array
 *                   items:
 *                     type: object
 *                 Records:
 *                   type: array
 *                   items:
 *                     type: object
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
 *  @swagger
 * /read:
 *   get:
 *     summary: Retrieve data based on user role
 *     description: Retrieves data based on the user's role (Admin, Security, or Visitor)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Admins:
 *                   type: array
 *                   items:
 *                     type: object
 *                 Security:
 *                   type: object
 *                 Visitors:
 *                   type: array
 *                   items:
 *                     type: object
 *                 Records:
 *                   type: array
 *                   items:
 *                     type: object
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
 * /checkIn:
 *   post:
 *     summary: Check-in for Visitors
 *     description: Allows Security to check-in Visitor to a location
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               recordID:
 *                 type: string
 *               purpose:
 *                 type: string
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '403':
 *         description: Only visitors can check-in
 *       '404':
 *         description: User not found or already checked in
 *       '409':
 *         description: RecordID already in use
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Visitor
 */

    app.post('/checkIn', authenticateToken, async (req, res) => {
      let data = req.user;
      let DataVis = req.body;
      res.send(await checkIn(client, data, DataVis));
    });
    
/**
 * @swagger
 * /checkOut:
 *   patch:
 *     summary: Check-out for Visitors
 *     description: Allows visitors to check-out from a location
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '401':
 *         description: Unauthorized or Invalid token
 *       '404':
 *         description: User not found or not checked in
 *       '500':
 *         description: Internal server error
 *     tags:
 *       - Visitor 
 */
    app.patch('/checkOut', authenticateToken, async (req, res) => {
      let data = req.user;
      res.send(await checkOut(client, data));
    });
} catch (e) {
    console.error(e);

  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.error);
//encrypt Password
  async function encryptPassword(password) {
    const hash = await bcrypt.hash(password, saltRounds);
     return hash;
    }
  async function decryptPassword(password, compare) {
      const match = await bcrypt.compare(password, compare)
      return match
    
    }
    //register admin 
  async function regAdmin(client, data) {
    const existingAdmin = await client
      .db("Admin")
      .collection("data")
      .findOne({ username: data.username, role: "Admin" });
  
    if (existingAdmin) {
      return "Admin already registered";
    }else {
      data.password = await encryptPassword(data.password);
      data.role = "Admin";
    const result = await client.db("Admin").collection("data").insertOne(data);
    return 'Admin registered';
    }
      }
    //register function
    async function register(client, data, DataVis) {

      temporary = await client.db('Admin').collection('data').findOne({username: DataVis.username})
    if(!temporary) {
    
      if (data.role === 'Admin') {
        const result = await client.db('Admin').collection('data').insertOne({
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
    }}
    async function Securityregister(client, data, DataVis) {

      temporary = await client.db('Security').collection('data').findOne({username: DataVis.username})
    if(!temporary) {
    if (data.role === 'Security') {
      const visitorPassIdentifier = generateVisitorPassIdentifier();
      const currentCheckInTime = new Date();
      const result = await client.db('Visitor').collection('data').insertOne({
        name: DataVis.name,
        ic: DataVis.ic,
        email: DataVis.email,
        phone: DataVis.phone,
        vehicleNo: DataVis.vehicleNo,
        department: DataVis.department,
        company: DataVis.company,
        role: 'Visitor',
        security: data.username,
        passvisitor: visitorPassIdentifier
      });
      
      
      var message = "Visitor registered successfully\n Visitor Pass Identifier: " + visitorPassIdentifier ;
      return message}
     else {
      return 'Username already in use, please enter another username'
    }}else{
      return 'You are not allowed to register';}}

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
  //read from token and checking role to display 
  async function read(client, data) {
    if(data.role == 'Admin') {
      Admins = await client.db('Admin').collection('data').find({role:"Admin"}).next() //.next to read in object instead of array
      Security = await client.db('Security').collection('data').find({role:"Security"}).toArray()
      Visitors = await client.db('Visitor').collection('data').find({role:"Visitor"}).toArray()
      PassVisitor = await client.db('Visitor').collection('PassVisitor').find().next()
      return {Admins, Security, Visitors, PassVisitor}
      }
  
    if (data.role == 'Security') {
      Security = await client.db('Security').collection('data').findOne({username: data.username})
      Visitors = await client.db('Visitor').collection('data').find({security: data.username}).toArray()   
      PassVisitor = await client.db('Visitor').collection('PassVisitor').find({username: {$in:Security.visitors}}).toArray()
      return {Security, Visitors, PassVisitor}
      }
  }

 //login 
  async function login(client, data) {
    const user = await client
      .db("Admin")
      .collection("data")
      .findOne({ username: data.username });
  
    if (user) {
      const isPasswordMatch = await decryptPassword(data.password, user.password);
  
      if (isPasswordMatch) {
        
        return Display(user.role);
        
      } else {
        return "Wrong password";
      }
    } else {
      return "User not found";
    }
  }
   //login 
   async function login(client, data) {
    const user = await client
      .db("Security")
      .collection("data")
      .findOne({ username: data.username });
  
    if (user) {
      const isPasswordMatch = await decryptPassword(data.password, user.password);
  
      if (isPasswordMatch) {
        
        return Display(user.role);
        
      } else {
        return "Wrong password";
      }
    } else {
      return "User not found";
    }
  }
  //output 
  function Display(data) {
    if(data == 'Admin') {
      var message="You are logged in as Admin\n You can Access:\n 1.Register Security\n 2. Read All Users and Records\n\n Token for " + user.name + ": " + generateToken(user);
      return message
    } else if (data == 'Security') {
      var message="You are logged in as Security\n You can Access:\n 1.Register Visitor\n 2. Check My Data, My Visitors and Their Records' Data\n 3. Update Visitor Data\n 4. Delete My Data\n\n Token for " + user.name +": " + generateToken(user);
      return message
    } 
  }
  

    // Check-in 
    async function checkIn(client, data, DataVis) {
      const usersCollection = client.db('Visitor').collection('data');
    
      const currentUser = await usersCollection.findOne({ PassVisitor: data.PassVisitor });
    
      if (!currentUser) {
        return 'Visitor not found';
      }
    
      if (currentUser.currentCheckIn) {
        return 'Already Given The Pass';
      }
      const currentCheckInTime = new Date();
    
      const recordData = {
        P: DataVis.recordID,
        purpose: DataVis.purpose,
        checkInTime: currentCheckInTime
      };
    
      await recordsCollection.insertOne(recordData);
    
      await usersCollection.updateOne(
        { username: data.username },
        {
          $set: { currentCheckIn: DataVis.recordID },
          $push: { records: DataVis.recordID }
        }
      );
    
      return `You have checked in at '${currentCheckInTime}' with recordID '${DataVis.recordID}'`;
    }
  // Check-out operation
  //Function to check out
async function checkOut(client, data) {
  const usersCollection = client.db('labdata').collection('data');
  const recordsCollection = client.db('labdata').collection('Records');

  const currentUser = await usersCollection.findOne({ username: data.username });

  if (!currentUser) {
    return 'User not found';
  }

  if (!currentUser.currentCheckIn) {
    return 'You have not checked in yet, please check in first!!!';
  }

  const checkOutTime = new Date();

  const updateResult = await recordsCollection.updateOne(
    { recordID: currentUser.currentCheckIn },
    { $set: { checkOutTime: checkOutTime } }
  );

  if (updateResult.modifiedCount === 0) {
    return 'Failed to update check-out time. Please try again.';
  }

  const unsetResult = await usersCollection.updateOne(
    { username: currentUser.username },
    { $unset: { currentCheckIn: 1 } }
  );

  if (unsetResult.modifiedCount === 0) {
    return 'Failed to check out. Please try again.';
  }

  return `You have checked out at '${checkOutTime}' with recordID '${currentUser.currentCheckIn}'`;
}
function generateVisitorPassIdentifier() {
  const length = 8; // Length of the identifier
  const charset = "abcdefghijklmnopqrstuvmxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // Characters to include in the identifier
  let identifier = "";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    identifier += charset[randomIndex];
  }
  return identifier;
}
