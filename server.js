require('dotenv').config({
  path: require('path').join(__dirname, '.env')
});

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

const PORT = process.env.PORT || 3000;
const UPLOADS = path.join(__dirname, 'public/uploads');

fs.mkdirSync(UPLOADS, { recursive: true });

if (!process.env.MONGODB_URI) {
  console.error('ERROR: MONGODB_URI is missing in .env');
  process.exit(1);
}

const oid = mongoose.Schema.Types.ObjectId;

/* =========================================================
   DATABASE SCHEMAS
========================================================= */

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true
  },

  password: {
    type: String,
    required: true
  },

  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },

  createdDate: {
    type: Date,
    default: Date.now
  }
});


const reportSchema = new mongoose.Schema({
  userId: {
    type: oid,
    ref: 'User',
    required: true
  },

  reportType: {
    type: String,
    enum: ['lost', 'found'],
    required: true
  },

  description: {
    type: String,
    required: true
  },

  image: String,

  location: {
    type: String,
    required: true
  },

  date: {
    type: String,
    required: true
  },

  status: {
    type: String,
    enum: [
      'قيد المراجعة',
      'موثوق',
      'يحتاج إلى تحقق إضافي',
      'غير موثوق',
      'مغلق'
    ],
    default: 'قيد المراجعة'
  }

}, {
  timestamps: true
});


const notificationSchema = new mongoose.Schema({
  userId: {
    type: oid,
    ref: 'User',
    required: true
  },

  reportId: {
    type: oid,
    ref: 'Report',
    default: null
  },

  type: String,

  message: String,

  date: {
    type: Date,
    default: Date.now
  },

  status: {
    type: String,
    enum: ['unread', 'read'],
    default: 'unread'
  }
});


const verificationSchema = new mongoose.Schema({
  reportId: {
    type: oid,
    ref: 'Report'
  },

  adminId: {
    type: oid,
    ref: 'User'
  },

  evaluation: String,

  status: String,

  verificationDate: {
    type: Date,
    default: Date.now
  }
});


const messageSchema = new mongoose.Schema({
  senderId: {
    type: oid,
    ref: 'User',
    required: true
  },

  receiverId: {
    type: oid,
    ref: 'User',
    required: true
  },

  reportId: {
    type: oid,
    ref: 'Report',
    default: null
  },

  messageText: {
    type: String,
    required: true
  },

  date: {
    type: Date,
    default: Date.now
  }
});

messageSchema.index({
  senderId: 1,
  receiverId: 1,
  date: 1
});


const User = mongoose.model('User', userSchema);
const Report = mongoose.model('Report', reportSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Verification = mongoose.model('Verification', verificationSchema);
const Message = mongoose.model('Message', messageSchema);


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);


app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secret',

    resave: false,

    saveUninitialized: false,

    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions'
    }),

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);


app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);


/* =========================================================
   IMAGE UPLOAD
========================================================= */

const storage = multer.diskStorage({

  destination: (_, __, cb) => {
    cb(null, UPLOADS);
  },

  filename: (_, file, cb) => {

    cb(
      null,
      Date.now() +
      '-' +
      Math.random()
        .toString(36)
        .slice(2) +
      path.extname(file.originalname).toLowerCase()
    );

  }

});


const upload = multer({

  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (_, file, cb) => {

    if (
      /^image\/(jpeg|png|webp|gif)$/.test(
        file.mimetype
      )
    ) {

      cb(null, true);

    } else {

      cb(
        new Error('يسمح بالصور فقط'),
        false
      );

    }

  }

});


/* =========================================================
   HELPERS
========================================================= */

const clean = x =>
  typeof x === 'string'
    ? x.trim()
    : '';


const id = x =>
  new mongoose.Types.ObjectId(x);


/*
   تحويل بيانات المستخدم إلى البيانات التي يستخدمها
   الـFrontend
*/

function pub(u) {

  return {

    User_ID: String(u._id),

    Name: u.name,

    Email: u.email,

    Role: u.role

  };

}


/* =========================================================
   AUTHENTICATION
========================================================= */

function auth(req, res, next) {

  if (!req.session.user) {

    return res.status(401).json({
      message: 'يجب تسجيل الدخول'
    });

  }

  next();

}


/* =========================================================
   ADMIN AUTHENTICATION
========================================================= */

/*
   مهم جدًا:

   لا نعتمد على role الموجود داخل Session فقط.

   نقوم كل مرة بالرجوع إلى MongoDB Atlas
   والتأكد من role الحقيقي للمستخدم.
*/

async function admin(req, res, next) {

  try {

    if (
      !req.session.user ||
      !req.session.user.User_ID
    ) {

      return res.status(401).json({
        message: 'يجب تسجيل الدخول'
      });

    }


    const user =
      await User.findById(
        req.session.user.User_ID
      )
      .select('_id name email role')
      .lean();


    if (!user) {

      return res.status(401).json({
        message: 'الجلسة غير صالحة، سجل الدخول من جديد'
      });

    }


    /*
       هنا يتم التأكد الحقيقي من MongoDB
    */

    if (user.role !== 'admin') {

      return res.status(403).json({
        message:
          'حسابك ليس مسؤولاً. تأكد أن role = admin في MongoDB Atlas'
      });

    }


    /*
       تحديث الـSession بالبيانات الجديدة
    */

    req.session.user = pub(user);


    next();

  } catch (error) {

    console.error(
      'Admin verification error:',
      error
    );

    return res.status(500).json({
      message:
        'حدث خطأ أثناء التحقق من صلاحيات المسؤول'
    });

  }

}


/* =========================================================
   CURRENT USER
========================================================= */

app.get('/api/me', async (req, res) => {

  try {

    if (!req.session.user) {

      return res.json({
        user: null
      });

    }


    const user =
      await User.findById(
        req.session.user.User_ID
      )
      .select('_id name email role')
      .lean();


    if (!user) {

      req.session.destroy(() => {});

      return res.json({
        user: null
      });

    }


    /*
       تحديث Session بالبيانات الحالية
       من MongoDB
    */

    req.session.user = pub(user);


    res.json({
      user: req.session.user
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'حدث خطأ'
    });

  }

});


/* =========================================================
   ADMIN TEST
========================================================= */

app.get(
  '/api/admin/me',
  admin,
  (req, res) => {

    res.json({
      admin: true,
      user: req.session.user
    });

  }
);


/* =========================================================
   REGISTER
========================================================= */

app.post(
  '/api/register',
  async (req, res) => {

    try {

      const name =
        clean(req.body.name);

      const email =
        clean(req.body.email)
          .toLowerCase();

      const password =
        req.body.password || '';


      if (
        !name ||
        !email ||
        password.length < 6
      ) {

        return res.status(400).json({
          message:
            'أكمل البيانات وكلمة المرور 6 أحرف على الأقل'
        });

      }


      if (
        await User.findOne({ email })
      ) {

        return res.status(409).json({
          message:
            'البريد مستخدم بالفعل'
        });

      }


      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );


      const u =
        await User.create({

          name,

          email,

          password:
            hashedPassword

        });


      /*
         إنشاء Session جديدة
      */

      await new Promise(
        (resolve, reject) => {

          req.session.regenerate(
            err => {

              if (err)
                return reject(err);

              resolve();

            }
          );

        }
      );


      req.session.user =
        pub(u);


      await new Promise(
        (resolve, reject) => {

          req.session.save(
            err => {

              if (err)
                return reject(err);

              resolve();

            }
          );

        }
      );


      res.json({
        user:
          req.session.user
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({
        message: e.message
      });

    }

  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/login',
  async (req, res) => {

    try {

      const email =
        clean(req.body.email)
          .toLowerCase();


      const password =
        req.body.password || '';


      const u =
        await User.findOne({
          email
        });


      if (
        !u ||
        !(await bcrypt.compare(
          password,
          u.password
        ))
      ) {

        return res.status(401).json({
          message:
            'بيانات الدخول غير صحيحة'
        });

      }


      /*
         إذا كان البريد المحدد في .env
         هو بريد المسؤول، نجعل الحساب Admin.
      */

      const configuredAdmin =
        (
          process.env.ADMIN_EMAIL ||
          ''
        )
        .trim()
        .toLowerCase();


      if (
        configuredAdmin &&
        email === configuredAdmin &&
        u.role !== 'admin'
      ) {

        u.role = 'admin';

        await u.save();

      }


      /*
         إعادة إنشاء Session جديدة بالكامل
         لمنع بقاء role القديم.
      */

      await new Promise(
        (resolve, reject) => {

          req.session.regenerate(
            err => {

              if (err)
                return reject(err);

              resolve();

            }
          );

        }
      );


      /*
         نقرأ الحساب مرة أخرى من MongoDB
         بعد تعديل role.
      */

      const freshUser =
        await User.findById(
          u._id
        )
        .select(
          '_id name email role'
        );


      req.session.user =
        pub(freshUser);


      await new Promise(
        (resolve, reject) => {

          req.session.save(
            err => {

              if (err)
                return reject(err);

              resolve();

            }
          );

        }
      );


      console.log(
        'LOGIN:',
        freshUser.email,
        'ROLE:',
        freshUser.role
      );


      res.json({
        user:
          req.session.user
      });


    } catch (error) {

      console.error(
        'Login error:',
        error
      );


      res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الدخول'
      });

    }

  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  '/api/logout',
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          ok: true
        });

      }
    );

  }
);


/* =========================================================
   REPORTS
========================================================= */

app.get(
  '/api/reports',
  async (req, res) => {

    const q =
      clean(req.query.q);

    const type =
      clean(req.query.type);

    const f = {};


    if (type) {

      f.reportType = type;

    }


    if (q) {

      f.$or = [

        {
          description: {
            $regex: q,
            $options: 'i'
          }
        },

        {
          location: {
            $regex: q,
            $options: 'i'
          }
        }

      ];

    }


    const rows =
      await Report.find(f)
        .populate(
          'userId',
          'name email'
        )
        .sort({
          createdAt: -1
        })
        .lean();


    res.json(

      rows.map(r => ({

        ...r,

        Report_ID:
          String(r._id),

        User_ID:
          String(r.userId._id),

        OwnerName:
          r.userId.name,

        OwnerEmail:
          r.userId.email

      }))

    );

  }
);


app.get(
  '/api/reports/:id',
  async (req, res) => {

    const r =
      await Report.findById(
        req.params.id
      )
      .populate(
        'userId',
        'name email'
      )
      .lean();


    if (!r) {

      return res.status(404).json({
        message:
          'البلاغ غير موجود'
      });

    }


    res.json({

      ...r,

      Report_ID:
        String(r._id),

      User_ID:
        String(r.userId._id),

      OwnerName:
        r.userId.name,

      OwnerEmail:
        r.userId.email

    });

  }
);


app.get(
  '/api/my-reports',
  auth,
  async (req, res) => {

    const rows =
      await Report.find({

        userId:
          req.session.user.User_ID

      })
      .sort({
        createdAt: -1
      })
      .lean();


    res.json(

      rows.map(r => ({

        ...r,

        Report_ID:
          String(r._id)

      }))

    );

  }
);


/* =========================================================
   CREATE REPORT
========================================================= */

app.post(
  '/api/reports',
  auth,
  upload.single('image'),
  async (req, res) => {

    const {
      type,
      description,
      location,
      date
    } = req.body;


    if (
      !['lost', 'found']
        .includes(type) ||

      !clean(description) ||

      !clean(location) ||

      !clean(date)
    ) {

      return res.status(400).json({
        message:
          'أكمل بيانات البلاغ'
      });

    }


    const r =
      await Report.create({

        userId:
          req.session.user.User_ID,

        reportType:
          type,

        description:
          clean(description),

        location:
          clean(location),

        date:
          clean(date),

        image:
          req.file
            ? '/uploads/' +
              req.file.filename
            : null

      });


    res.json({

      message:
        'تم إنشاء البلاغ',

      reportId:
        String(r._id)

    });

  }
);


/* =========================================================
   UPDATE REPORT
========================================================= */

app.put(
  '/api/reports/:id',
  auth,
  upload.single('image'),
  async (req, res) => {

    const r =
      await Report.findById(
        req.params.id
      );


    if (!r) {

      return res.status(404).json({
        message:
          'غير موجود'
      });

    }


    /*
       نتحقق من MongoDB مباشرة
       إذا كان المستخدم Admin.
    */

    const currentUser =
      await User.findById(
        req.session.user.User_ID
      )
      .select('role')
      .lean();


    const isAdmin =
      currentUser &&
      currentUser.role === 'admin';


    if (
      String(r.userId) !==
        String(req.session.user.User_ID)
      &&
      !isAdmin
    ) {

      return res.status(403).json({
        message:
          'لا يمكنك تعديل هذا البلاغ'
      });

    }


    r.description =
      clean(req.body.description) ||
      r.description;


    r.location =
      clean(req.body.location) ||
      r.location;


    r.date =
      clean(req.body.date) ||
      r.date;


    if (req.file) {

      r.image =
        '/uploads/' +
        req.file.filename;

    }


    await r.save();


    res.json({
      message:
        'تم التعديل'
    });

  }
);


/* =========================================================
   DELETE REPORT
========================================================= */

app.delete(
  '/api/reports/:id',
  auth,
  async (req, res) => {

    const r =
      await Report.findById(
        req.params.id
      );


    if (!r) {

      return res.status(404).json({
        message:
          'غير موجود'
      });

    }


    const currentUser =
      await User.findById(
        req.session.user.User_ID
      )
      .select('role')
      .lean();


    const isAdmin =
      currentUser &&
      currentUser.role === 'admin';


    if (
      String(r.userId) !==
        String(req.session.user.User_ID)
      &&
      !isAdmin
    ) {

      return res.status(403).json({
        message:
          'لا يمكنك حذف هذا البلاغ'
      });

    }


    if (r.image) {

      const f =
        path.join(
          __dirname,
          'public',
          r.image.replace(
            /^\//,
            ''
          )
        );


      if (fs.existsSync(f)) {

        fs.unlinkSync(f);

      }

    }


    await Promise.all([

      Report.deleteOne({
        _id: r._id
      }),

      Notification.deleteMany({
        reportId: r._id
      }),

      Verification.deleteMany({
        reportId: r._id
      }),

      Message.deleteMany({
        reportId: r._id
      })

    ]);


    res.json({
      message:
        'تم حذف البلاغ'
    });

  }
);


/* =========================================================
   USERS / COMMUNICATION
========================================================= */

app.get(
  '/api/users',
  auth,
  async (req, res) => {

    const users =
      await User.find({

        _id: {
          $ne:
            req.session.user.User_ID
        }

      })
      .select(
        'name email role'
      )
      .sort({
        name: 1
      })
      .lean();


    res.json(

      users.map(u => ({

        id:
          String(u._id),

        name:
          u.name,

        email:
          u.email,

        role:
          u.role

      }))

    );

  }
);


/* =========================================================
   CONVERSATIONS
========================================================= */

app.get(
  '/api/conversations',
  auth,
  async (req, res) => {

    const me =
      id(req.session.user.User_ID);


    const msgs =
      await Message.find({

        $or: [

          {
            senderId: me
          },

          {
            receiverId: me
          }

        ]

      })
      .populate(
        'senderId',
        'name email'
      )
      .populate(
        'receiverId',
        'name email'
      )
      .populate(
        'reportId',
        'description'
      )
      .sort({
        date: -1
      })
      .lean();


    const map =
      new Map();


    for (const m of msgs) {

      const other =
        String(m.senderId._id) ===
        String(me)
          ? m.receiverId
          : m.senderId;


      const key =
        String(other._id);


      if (!map.has(key)) {

        map.set(

          key,

          {

            userId:
              key,

            name:
              other.name,

            email:
              other.email,

            latest:
              m.messageText,

            date:
              m.date,

            reportId:
              m.reportId
                ? String(
                    m.reportId._id
                  )
                : null,

            reportDescription:
              m.reportId?.description ||
              ''

          }

        );

      }

    }


    res.json(
      [...map.values()]
    );

  }
);


/* =========================================================
   GET MESSAGES
========================================================= */

app.get(
  '/api/messages/:userId',
  auth,
  async (req, res) => {

    const me =
      req.session.user.User_ID;


    const other =
      clean(req.params.userId);


    if (
      !other ||
      other === 'undefined' ||
      !mongoose.isValidObjectId(
        other
      )
    ) {

      return res.status(400).json({
        message:
          'معرف المستخدم غير صحيح'
      });

    }


    const f = {

      $or: [

        {
          senderId: me,
          receiverId: other
        },

        {
          senderId: other,
          receiverId: me
        }

      ]

    };


    if (
      req.query.reportId &&
      mongoose.isValidObjectId(
        req.query.reportId
      )
    ) {

      f.reportId =
        req.query.reportId;

    }


    const rows =
      await Message.find(f)
        .populate(
          'senderId',
          'name'
        )
        .sort({
          date: 1
        })
        .lean();


    res.json(

      rows.map(m => ({

        id:
          String(m._id),

        senderId:
          String(m.senderId._id),

        senderName:
          m.senderId.name,

        receiverId:
          String(m.receiverId),

        reportId:
          m.reportId
            ? String(m.reportId)
            : null,

        text:
          m.messageText,

        date:
          m.date,

        mine:
          String(
            m.senderId._id
          ) ===
          String(me)

      }))

    );

  }
);


/* =========================================================
   SEND MESSAGE
========================================================= */

app.post(
  '/api/messages',
  auth,
  async (req, res) => {

    const receiverId =
      clean(req.body.receiverId);

    const text =
      clean(req.body.text);

    const reportId =
      clean(req.body.reportId) ||
      null;


    if (
      !mongoose.isValidObjectId(
        receiverId
      )
    ) {

      return res.status(400).json({
        message:
          'المستخدم غير صحيح'
      });

    }


    if (
      String(receiverId) ===
      String(
        req.session.user.User_ID
      )
    ) {

      return res.status(400).json({
        message:
          'لا يمكنك مراسلة نفسك'
      });

    }


    if (!text) {

      return res.status(400).json({
        message:
          'اكتب رسالة'
      });

    }


    const receiver =
      await User.findById(
        receiverId
      );


    if (!receiver) {

      return res.status(404).json({
        message:
          'المستخدم غير موجود'
      });

    }


    const m =
      await Message.create({

        senderId:
          req.session.user.User_ID,

        receiverId,

        reportId:
          mongoose.isValidObjectId(
            reportId
          )
            ? reportId
            : null,

        messageText:
          text

      });


    await Notification.create({

      userId:
        receiverId,

      reportId:
        m.reportId,

      type:
        'رسالة جديدة',

      message:
        `لديك رسالة جديدة من ${req.session.user.Name}`

    });


    res.json({

      message:
        'تم إرسال الرسالة',

      id:
        String(m._id)

    });

  }
);


/* =========================================================
   DELETE MESSAGE
========================================================= */

app.delete(
  '/api/messages/:id',
  auth,
  async (req, res) => {

    if (
      !mongoose.isValidObjectId(
        req.params.id
      )
    ) {

      return res.status(400).json({
        message:
          'رسالة غير صحيحة'
      });

    }


    const m =
      await Message.findById(
        req.params.id
      );


    if (!m) {

      return res.status(404).json({
        message:
          'الرسالة غير موجودة'
      });

    }


    const currentUser =
      await User.findById(
        req.session.user.User_ID
      )
      .select('role')
      .lean();


    const isAdmin =
      currentUser &&
      currentUser.role === 'admin';


    if (
      String(m.senderId) !==
        String(
          req.session.user.User_ID
        )
      &&
      !isAdmin
    ) {

      return res.status(403).json({
        message:
          'لا يمكنك حذف هذه الرسالة'
      });

    }


    await Message.deleteOne({
      _id: m._id
    });


    res.json({
      message:
        'تم حذف الرسالة'
    });

  }
);


/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get(
  '/api/notifications',
  auth,
  async (req, res) => {

    const rows =
      await Notification.find({

        userId:
          req.session.user.User_ID

      })
      .sort({
        date: -1
      })
      .lean();


    res.json(

      rows.map(n => ({

        ...n,

        id:
          String(n._id)

      }))

    );

  }
);


app.patch(
  '/api/notifications/:id/read',
  auth,
  async (req, res) => {

    await Notification.updateOne(

      {

        _id:
          req.params.id,

        userId:
          req.session.user.User_ID

      },

      {

        $set: {
          status: 'read'
        }

      }

    );


    res.json({
      ok: true
    });

  }
);


app.delete(
  '/api/notifications/:id',
  auth,
  async (req, res) => {

    await Notification.deleteOne({

      _id:
        req.params.id,

      userId:
        req.session.user.User_ID

    });


    res.json({
      ok: true
    });

  }
);


/* =========================================================
   ADMIN - STATISTICS
========================================================= */

app.get(
  '/api/admin/stats',
  admin,
  async (req, res) => {

    res.json({

      users:
        await User.countDocuments({
          role: 'user'
        }),

      reports:
        await Report.countDocuments(),

      pending:
        await Report.countDocuments({
          status: 'قيد المراجعة'
        }),

      verified:
        await Report.countDocuments({
          status: 'موثوق'
        })

    });

  }
);


/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
  '/api/admin/users',
  admin,
  async (req, res) => {

    const users =
      await User.find(
        {},
        'name email role createdDate'
      )
      .sort({
        createdDate: -1
      })
      .lean();


    res.json(users);

  }
);


/* =========================================================
   ADMIN - REPORTS
========================================================= */

app.get(
  '/api/admin/reports',
  admin,
  async (req, res) => {

    const rows =
      await Report.find()
        .populate(
          'userId',
          'name email'
        )
        .sort({
          createdAt: -1
        })
        .lean();


    res.json(

      rows.map(r => ({

        ...r,

        Report_ID:
          String(r._id),

        OwnerName:
          r.userId.name,

        OwnerEmail:
          r.userId.email

      }))

    );

  }
);


/* =========================================================
   ADMIN - CHANGE REPORT STATUS
========================================================= */

app.patch(
  '/api/admin/reports/:id/status',
  admin,
  async (req, res) => {

    const allowed = [

      'قيد المراجعة',

      'موثوق',

      'يحتاج إلى تحقق إضافي',

      'غير موثوق',

      'مغلق'

    ];


    const status =
      clean(req.body.status);


    if (
      !allowed.includes(status)
    ) {

      return res.status(400).json({
        message:
          'حالة غير صالحة'
      });

    }


    const r =
      await Report.findById(
        req.params.id
      );


    if (!r) {

      return res.status(404).json({
        message:
          'غير موجود'
      });

    }


    r.status =
      status;


    await r.save();


    await Verification.create({

      reportId:
        r._id,

      adminId:
        req.session.user.User_ID,

      status,

      evaluation:
        'مراجعة إدارية'

    });


    await Notification.create({

      userId:
        r.userId,

      reportId:
        r._id,

      type:
        'تحديث البلاغ',

      message:
        `تم تغيير حالة بلاغك إلى: ${status}`

    });


    res.json({
      message:
        'تم تحديث الحالة'
    });

  }
);


/* =========================================================
   ADMIN - DELETE USER
========================================================= */

app.delete(
  '/api/admin/users/:id',
  admin,
  async (req, res) => {

    if (
      String(req.params.id) ===
      String(
        req.session.user.User_ID
      )
    ) {

      return res.status(400).json({
        message:
          'لا يمكنك حذف حسابك'
      });

    }


    const u =
      await User.findById(
        req.params.id
      );


    if (!u) {

      return res.status(404).json({
        message:
          'المستخدم غير موجود'
      });

    }


    const reports =
      await Report.find({
        userId:
          u._id
      });


    await Promise.all(

      reports.map(r => {

        if (r.image) {

          const f =
            path.join(
              __dirname,
              'public',
              r.image.replace(
                /^\//,
                ''
              )
            );


          if (fs.existsSync(f)) {

            fs.unlinkSync(f);

          }

        }

      })

    );


    await Promise.all([

      Report.deleteMany({
        userId:
          u._id
      }),

      Message.deleteMany({

        $or: [

          {
            senderId:
              u._id
          },

          {
            receiverId:
              u._id
          }

        ]

      }),

      Notification.deleteMany({
        userId:
          u._id
      }),

      User.deleteOne({
        _id:
          u._id
      })

    ]);


    res.json({
      message:
        'تم حذف المستخدم وبياناته'
    });

  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(400).json({

      message:
        err.message ||
        'حدث خطأ'

    });

  }
);


/* =========================================================
   ADMIN SEED
========================================================= */

async function seed() {

  const email =
    (
      process.env.ADMIN_EMAIL ||
      ''
    )
    .trim()
    .toLowerCase();


  /*
     إذا لم يوجد ADMIN_EMAIL
     في .env لا ننشئ حسابًا تلقائيًا.
  */

  if (!email) {

    console.log(
      'ADMIN_EMAIL is not configured. Existing admin accounts are preserved.'
    );

    return;

  }


  const existing =
    await User.findOne({
      email
    });


  /*
     إذا كان الحساب غير موجود
     يتم إنشاؤه كمسؤول.
  */

  if (!existing) {

    const password =
      process.env.ADMIN_PASSWORD ||
      'ADMIN_PASSWORD';


    await User.create({

      name:
        process.env.ADMIN_NAME ||
        'مسؤول النظام',

      email,

      password:
        await bcrypt.hash(
          password,
          10
        ),

      role:
        'admin'

    });


    console.log(
      'Admin account created:',
      email
    );


  } else {

    /*
       إذا كان الحساب موجودًا
       نضمن أن role = admin.
    */

    if (
      existing.role !== 'admin'
    ) {

      existing.role =
        'admin';

      await existing.save();

    }


    console.log(
      'Admin account verified:',
      email
    );

  }

}


/* =========================================================
   START SERVER
========================================================= */

(async () => {

  try {

    await mongoose.connect(
      process.env.MONGODB_URI
    );


    console.log(
      'MongoDB Atlas connected successfully'
    );


    await seed();


    app.listen(
      PORT,
      () => {

        console.log(
          `http://localhost:${PORT}`
        );

      }
    );


  } catch (e) {

    console.error(
      'MongoDB connection failed:',
      e.message
    );


    process.exit(1);

  }

})();