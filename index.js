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
    app.post('/Adminlogin', async (req, res) => {
      let data = req.body;
      res.send(await Adminlogin(client, data));
    });


 /**
 * @swagger
 * /Securitylogin:
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
  app.post('/Securitylogin', async (req, res) => {
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
      const length = 8; // Length of the identifier
      const charset = "abcdefghijklmnopqrstuvmxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // Characters to include in the identifier
      let identifier = "";
    
      for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        identifier += charset[randomIndex];
      }
      return identifier;
    }
    
    //register admin 
  async function regAdmin(client, data) {
    const existingAdmin = await client
      .db("Admin1")
      .collection("data")
      .findOne({ username: data.username });
  
    if (existingAdmin) {
      return "Admin already registered";
    }else {
      data.password = await encryptPassword(data.password);
      data.role = "Admin";
      const result = await client.db("Admin1").collection("data").insertOne(data);
      return 'Admin registered';
    }
      }

       //login 
  async function Adminlogin(client, data) {
    const user = await client.db('Admin1').collection('data').findOne({ username: data.username });
    if (user) {
      const isPasswordMatch = await decryptPassword(data.password, user.password);
  
      if (isPasswordMatch) {
        
        return Display(user.role)," Token for " + user.role + ": " + generateToken(user);
        
        
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

    //register function
  async function register(client, data, DataVis) {
  // Check for existing username in the relevant collection
  const existingUser = await client.db('Security').collection('data').findOne({ username: DataVis.username });

  if (existingUser) {
    return 'Username already in use';
  }

  if (data.role === 'Admin') {
    return 'You are not allowed to register as Security';
  }

  // Register user as Security
  const result = await client.db('Security').collection('data').insertOne({
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

    async function Securityregister(client, data, DataVis) {

      temporary = await client.db('Security').collection('data').findOne({username: DataVis.username})
    if(!temporary) {
    if (data.role === 'Security') {
      const visitorPassIdentifier = generateVisitorPassIdentifier();
      const result = await client.db('Visitor').collection('data').insertOne({
        name: DataVis.name,
        ic: DataVis.ic,
        email: DataVis.email,
        phone: DataVis.phone,
        vehicleNo: DataVis.vehicleNo,
        department: DataVis.department,
        company: DataVis.company,
        role: 'Visitor',
        securityNumber: data.phone,
        passvisitor: visitorPassIdentifier
      });
      var message = 'Visitor registered successfully\n Visitor Pass Identifier: '+ visitorPassIdentifier ;
      return message}
     else {
      return 'Username already in use, please enter another username'
    }}else{
      return 'You are not allowed to register';}}

  
  //read from token and checking role to display 
  async function read(client, data) {
    if(data.role == 'Admin') {
      Admins = await client.db('Admin1').collection('data').find({role:"Admin"}).next() //.next to read in object instead of array
      Security = await client.db('Security').collection('data').find({role:"Security"}).toArray()
      Visitors = await client.db('Visitor').collection('data').find({role:"Visitor"}).toArray()
      return {Admins, Security, Visitors}
      }
  
    if (data.role == 'Security') {
      Security = await client.db('Security').collection('data').findOne({username: data.username})
      Visitors = await client.db('Visitor').collection('data').find({security: data.username}).toArray()   
      return {Security, Visitors}
      }
  }


  //output 
  function Display(data) {
    if(data == 'Admin') {
      var message="You are logged in as Admin\n You can Access:\n 1.Register Security\n 2. Read All Users and Records\n"
      return message
    } else if (data == 'Security') {
      var message="You are logged in as Security\n You can Access:\n 1.Register Visitor\n 2. Check My Data, My Visitors and Their Records' Data\n 3. Update Visitor Data\n 4. Delete My Data\n\n Token for " + data +": " + generateToken(data);
      return message
    } 
  }
