const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// 🔧 إعدادات CORS النهائية
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://construction-platform1.netlify.app/',
      'http://construction-platform1.netlify.app',
      'https://one23-2-ziy6.onrender.com',
      'http://one23-2-ziy6.onrender.com',
      'http://localhost:3000',
      'http://127.0.0.1:5500',
      'http://localhost:5500',
      '*'
    ];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'production') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// معالجة Preflight requests
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    return res.status(200).json({});
  }
  next();
});

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).send();
});

// Middlewares
app.use(express.json());

// تخزين رموز OTP مؤقتاً
const otpStorage = new Map();

// إعداد nodemailer لإرسال الإيميلات
const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// اتصال بقاعدة البيانات
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/buildmart', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ قاعدة البيانات متصلة'))
.catch(err => console.log('❌ خطأ في الاتصال:', err));

// نماذج البيانات
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'الاسم مطلوب'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'البريد الإلكتروني مطلوب'],
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'كلمة المرور مطلوبة'],
    minlength: [6, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل']
  },
  phone: {
    type: String,
    trim: true
  },
  address: {
    type: String,
    trim: true
  },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  isVerified: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// تشفير كلمة المرور قبل الحفظ
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// مقارنة كلمة المرور
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);

// نموذج المنتج
const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'اسم المنتج مطلوب'],
    trim: true
  },
  description: {
    type: String,
    required: [true, 'وصف المنتج مطلوب']
  },
  price: {
    type: Number,
    required: [true, 'سعر المنتج مطلوب'],
    min: [0, 'السعر لا يمكن أن يكون سالب']
  },
  category: {
    type: String,
    required: [true, 'فئة المنتج مطلوبة'],
    enum: ['مواد أساسية', 'مواد بناء', 'ادوات كهربائية', 'ادوات صحية']
  },
  image: {
    type: String,
    default: '/images/default-product.jpg'
  },
  stock: {
    type: Number,
    required: [true, 'الكمية المتاحة مطلوبة'],
    min: [0, 'الكمية لا يمكن أن تكون سالبة']
  },
  supplier: {
    type: String,
    required: [true, 'المورد مطلوب']
  },
  unit: {
    type: String,
    required: [true, 'وحدة القياس مطلوبة'],
    enum: ['كيلو', 'طن', 'متر', 'علبة', 'كيس']
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

const Product = mongoose.model('Product', productSchema);

// نموذج الطلب
const orderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  products: [{
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    },
    name: String,
    price: Number,
    quantity: {
      type: Number,
      required: true,
      min: 1
    }
  }],
  totalAmount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  shippingAddress: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'bank_transfer'],
    default: 'cash'
  }
}, {
  timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

// إضافة بيانات تجريبية للمنتجات
const addSampleProducts = async () => {
  try {
    const productsCount = await Product.countDocuments();
    
    if (productsCount === 0) {
      await Product.create([
        {
          name: 'أسمنت أبيض',
          description: 'أسمنت أبيض عالي الجودة للمباني',
          price: 25,
          category: 'مواد أساسية',
          image: '/images/cement.jpg',
          stock: 1000,
          supplier: 'شركة الاسمنت الوطنية',
          unit: 'كيس'
        },
        {
          name: 'رمل ناعم',
          description: 'رمل ناعم للبناء واللياسة',
          price: 12,
          category: 'مواد أساسية', 
          image: '/images/sand.jpg',
          stock: 5000,
          supplier: 'محاجر الرياض',
          unit: 'طن'
        },
        {
          name: 'طوب أحمر',
          description: 'طوب أحمر عالي الجودة',
          price: 8,
          category: 'مواد بناء',
          image: '/images/bricks.jpg',
          stock: 20000,
          supplier: 'مصنع الطوب الأحمر',
          unit: 'قطعة'
        }
      ]);
      console.log('✅ تم إضافة المنتجات التجريبية');
    }
  } catch (error) {
    console.log('❌ خطأ في إضافة المنتجات التجريبية:', error.message);
  }
};

// استدعاء الدالة عند تشغيل السيرفر
addSampleProducts();

// إنشاء JWT token
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'fallback_secret_key_2024', {
    expiresIn: process.env.JWT_EXPIRES_IN || '90d'
  });
};

// Middleware للتحقق من التوكن
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'غير مصرح بالدخول، يرجى تسجيل الدخول'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key_2024');
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        success: false,
        message: 'المستخدم لم يعد موجوداً'
      });
    }

    req.user = currentUser;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'جلسة منتهية، يرجى تسجيل الدخول مرة أخرى'
    });
  }
};

// 📧 إرسال رمز التحقق
const sendVerificationEmail = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'رمز التحقق - منصة مواد البناء',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">مرحباً بك في منصة مواد البناء</h2>
          <p>رمز التحقق الخاص بك هو:</p>
          <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${otp}
          </div>
          <p>هذا الرمز صالح لمدة 10 دقائق</p>
          <p>إذا لم تطلب هذا الرمز، يرجى تجاهل هذا الإيميل</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.log('خطأ في إرسال الإيميل:', error);
    return false;
  }
};

// 🔐 APIs المصادقة مع OTP

// إرسال رمز التحقق
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني مطلوب'
      });
    }

    // إنشاء رمز OTP عشوائي
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 دقائق

    // حفظ OTP في الذاكرة
    otpStorage.set(email, { otp, expiresAt });

    // إرسال الإيميل
    const emailSent = await sendVerificationEmail(email, otp);

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: 'خطأ في إرسال رمز التحقق'
      });
    }

    res.status(200).json({
      success: true,
      message: 'تم إرسال رمز التحقق إلى بريدك الإلكتروني'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في إرسال رمز التحقق',
      error: error.message
    });
  }
});

// تسجيل مستخدم جديد مع OTP
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone, address, otp } = req.body;

    if (!name || !email || !password || !otp) {
      return res.status(400).json({
        success: false,
        message: 'الاسم، البريد الإلكتروني، كلمة المرور ورمز التحقق مطلوبة'
      });
    }

    // التحقق من OTP
    const storedOtp = otpStorage.get(email);
    if (!storedOtp || storedOtp.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: 'رمز التحقق غير صحيح'
      });
    }

    if (Date.now() > storedOtp.expiresAt) {
      otpStorage.delete(email);
      return res.status(400).json({
        success: false,
        message: 'رمز التحقق منتهي الصلاحية'
      });
    }

    // التحقق إذا المستخدم موجود مسبقاً
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني مسجل مسبقاً'
      });
    }

    // إنشاء المستخدم
    const newUser = await User.create({
      name,
      email,
      password,
      phone,
      address,
      isVerified: true
    });

    // مسح OTP بعد الاستخدام
    otpStorage.delete(email);

    const token = signToken(newUser._id);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isVerified: newUser.isVerified
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في السيرفر',
      error: error.message
    });
  }
});

// تسجيل الدخول مع OTP
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, otp } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني وكلمة المرور مطلوبان'
      });
    }

    // إذا تم إرسال OTP، التحقق منه
    if (otp) {
      const storedOtp = otpStorage.get(email);
      if (!storedOtp || storedOtp.otp !== otp) {
        return res.status(400).json({
          success: false,
          message: 'رمز التحقق غير صحيح'
        });
      }

      if (Date.now() > storedOtp.expiresAt) {
        otpStorage.delete(email);
        return res.status(400).json({
          success: false,
          message: 'رمز التحقق منتهي الصلاحية'
        });
      }
    }

    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
      });
    }

    // إذا كان OTP مطلوب ولم يتم إرساله
    if (!otp && process.env.REQUIRE_OTP === 'true') {
      // إرسال OTP لتسجيل الدخول
      const loginOtp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = Date.now() + 10 * 60 * 1000;
      
      otpStorage.set(email, { otp: loginOtp, expiresAt, purpose: 'login' });
      
      await sendVerificationEmail(email, loginOtp);

      return res.status(200).json({
        success: true,
        requiresOtp: true,
        message: 'تم إرسال رمز التحقق إلى بريدك الإلكتروني'
      });
    }

    // مسح OTP بعد الاستخدام الناجح
    if (otp) {
      otpStorage.delete(email);
    }

    const token = signToken(user._id);

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في السيرفر',
      error: error.message
    });
  }
});

// باقي الـ APIs تبقى كما هي...
app.get('/api/auth/me', protect, async (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      phone: req.user.phone,
      address: req.user.address,
      isVerified: req.user.isVerified
    }
  });
});

// 🛍️ Products APIs
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ isActive: true });
    
    res.status(200).json({
      success: true,
      count: products.length,
      products
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب المنتجات',
      error: error.message
    });
  }
});

app.get('/api/products/search', async (req, res) => {
  try {
    const { q, category, minPrice, maxPrice } = req.query;
    
    let filter = { isActive: true };
    
    if (q) {
      filter.name = { $regex: q, $options: 'i' };
    }
    
    if (category) {
      filter.category = category;
    }
    
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }

    const products = await Product.find(filter);
    
    res.status(200).json({
      success: true,
      count: products.length,
      products
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في البحث',
      error: error.message
    });
  }
});

// 📦 Orders APIs
app.post('/api/orders', protect, async (req, res) => {
  try {
    const { products, totalAmount, shippingAddress, phone, paymentMethod } = req.body;

    if (!products || !totalAmount || !shippingAddress || !phone) {
      return res.status(400).json({
        success: false,
        message: 'المنتجات، المبلغ الإجمالي، العنوان ورقم الجوال مطلوبة'
      });
    }

    const newOrder = await Order.create({
      user: req.user._id,
      products,
      totalAmount,
      shippingAddress,
      phone,
      paymentMethod: paymentMethod || 'cash'
    });

    const orderWithUser = await Order.findById(newOrder._id).populate('user', 'name email phone');

    res.status(201).json({
      success: true,
      message: 'تم إنشاء الطلب بنجاح',
      order: orderWithUser
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في إنشاء الطلب',
      error: error.message
    });
  }
});

app.get('/api/orders/my-orders', protect, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user._id })
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: orders.length,
      orders
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الطلبات',
      error: error.message
    });
  }
});

// 🔔 Notifications API
app.get('/api/notifications', protect, async (req, res) => {
  try {
    const notifications = [
      {
        id: 1,
        title: 'مرحباً بك في بناء مارت',
        message: 'تم إنشاء حسابك بنجاح',
        type: 'info',
        isRead: false,
        createdAt: new Date()
      },
      {
        id: 2,
        title: 'عرض خاص',
        message: 'خصم 10% على جميع مواد البناء هذا الأسبوع',
        type: 'promotion', 
        isRead: false,
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
      }
    ];

    res.status(200).json({
      success: true,
      count: notifications.length,
      notifications
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الإشعارات',
      error: error.message
    });
  }
});

// Route أساسي
app.get('/', (req, res) => {
  res.json({ 
    message: 'بناء مارت - Backend شغال!',
    status: 'نجاح',
    version: '3.0.0',
    features: ['CORS كامل', 'نظام OTP', 'تسجيل آمن']
  });
});

// صفحة 404 للروابط غير الموجودة
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'الصفحة غير موجودة',
    path: req.originalUrl
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ السيرفر شغال على البورت ${PORT}`);
  console.log(`🌐 CORS مفعل لجميع النطاقات`);
  console.log(`📧 نظام OTP جاهز`);
});
