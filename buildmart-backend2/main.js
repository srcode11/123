const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// 🔧 إعدادات CORS مبسطة وآمنة للفرونت
const allowedOrigins = [
  'https://construction-platform1.netlify.app',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'https://one23-6-l3re.onrender.com',
  'https://your-frontend-domain.com' // أضف نطاقك هنا
];

app.use(cors({
  origin: function(origin, callback) {
    // السماح للطلبات بدون origin (مثل Postman) أو للـ origins المسموح بها
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS Blocked for origin:', origin);
      // بدل رمي error، نرجع response مناسبة
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// معالجة Preflight requests تلقائياً
app.options('*', cors());

// Middlewares
app.use(express.json());

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
    default: 'https://via.placeholder.com/300x200?text=منتج+بناء'
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
          image: 'https://via.placeholder.com/300x200?text=أسمنت+أبيض',
          stock: 1000,
          supplier: 'شركة الاسمنت الوطنية',
          unit: 'كيس'
        },
        {
          name: 'رمل ناعم',
          description: 'رمل ناعم للبناء واللياسة',
          price: 12,
          category: 'مواد أساسية', 
          image: 'https://via.placeholder.com/300x200?text=رمل+ناعم',
          stock: 5000,
          supplier: 'محاجر الرياض',
          unit: 'طن'
        },
        {
          name: 'طوب أحمر',
          description: 'طوب أحمر عالي الجودة',
          price: 8,
          category: 'مواد بناء',
          image: 'https://via.placeholder.com/300x200?text=طوب+أحمر',
          stock: 20000,
          supplier: 'مصنع الطوب الأحمر',
          unit: 'قطعة'
        },
        {
          name: 'أسلاك كهربائية',
          description: 'أسلاك كهربائية عالية الجودة',
          price: 15,
          category: 'ادوات كهربائية',
          image: 'https://via.placeholder.com/300x200?text=أسلاك+كهربائية',
          stock: 500,
          supplier: 'شركة الكهرباء الوطنية',
          unit: 'متر'
        },
        {
          name: 'مواسير PVC',
          description: 'مواسير PVC للصرف الصحي',
          price: 30,
          category: 'ادوات صحية',
          image: 'https://via.placeholder.com/300x200?text=مواسير+PVC',
          stock: 800,
          supplier: 'مصنع المواسير',
          unit: 'متر'
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

// Route أساسي
app.get('/', (req, res) => {
  res.json({ 
    message: 'بناء مارت - Backend شغال!',
    status: 'نجاح',
    version: '3.0.0',
    cors: 'مفعل للنطاقات المسموحة',
    allowedOrigins: allowedOrigins
  });
});

// 🔐 Authentication APIs
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone, address } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'الاسم، البريد الإلكتروني وكلمة المرور مطلوبة'
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني مسجل مسبقاً'
      });
    }

    const newUser = await User.create({
      name,
      email,
      password,
      phone,
      address
    });

    const token = signToken(newUser._id);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'البريد الإلكتروني وكلمة المرور مطلوبان'
      });
    }

    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
      });
    }

    const token = signToken(user._id);

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
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

app.get('/api/auth/me', protect, async (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      phone: req.user.phone,
      address: req.user.address
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

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'المنتج غير موجود'
      });
    }

    res.status(200).json({
      success: true,
      product
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب المنتج',
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

app.get('/api/orders/:id', protect, async (req, res) => {
  try {
    const order = await Order.findOne({ 
      _id: req.params.id, 
      user: req.user._id 
    });

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'الطلب غير موجود'
      });
    }

    res.status(200).json({
      success: true,
      order
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الطلب',
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

// 📊 Statistics API (للأدمن)
app.get('/api/stats', protect, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'غير مصرح بالوصول'
      });
    }

    const usersCount = await User.countDocuments();
    const productsCount = await Product.countDocuments();
    const ordersCount = await Order.countDocuments();
    const totalRevenue = await Order.aggregate([
      { $match: { status: { $ne: 'cancelled' } } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);

    res.status(200).json({
      success: true,
      stats: {
        users: usersCount,
        products: productsCount,
        orders: ordersCount,
        revenue: totalRevenue[0]?.total || 0
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الإحصائيات',
      error: error.message
    });
  }
});

// صفحة 404 للروابط غير الموجودة
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'الصفحة غير موجودة',
    path: req.originalUrl
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global Error:', error);
  res.status(500).json({
    success: false,
    message: 'حدث خطأ غير متوقع في السيرفر',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ السيرفر شغال على البورت ${PORT}`);
  console.log(`🌐 CORS مفعل للنطاقات: ${allowedOrigins.join(', ')}`);
  console.log(`🚀 Ready to accept requests from allowed origins`);
});
