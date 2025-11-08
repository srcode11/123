const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// 🔒 إعدادات الأمان
app.use(helmet({
  crossOriginResourcePolicy: { policy: "same-site" }
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.com'] 
    : ['http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());

// ⚡ معدل الطلبات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// 🔐 اتصال آمن بقاعدة البيانات
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ قاعدة البيانات متصلة آمنياً'))
.catch(err => console.log('❌ خطأ في الاتصال:', err.message));

// 🏗️ نماذج البيانات
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'الاسم مطلوب'],
    trim: true,
    minlength: [2, 'الاسم يجب أن يكون على الأقل حرفين'],
    maxlength: [50, 'الاسم لا يمكن أن يزيد عن 50 حرف']
  },
  email: {
    type: String,
    required: [true, 'البريد الإلكتروني مطلوب'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'البريد الإلكتروني غير صالح']
  },
  password: {
    type: String,
    required: [true, 'كلمة المرور مطلوبة'],
    minlength: [8, 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'],
    select: false
  },
  phone: {
    type: String,
    trim: true,
    match: [/^[0-9]{10}$/, 'رقم الجوال يجب أن يكون 10 أرقام']
  },
  address: {
    type: String,
    trim: true,
    maxlength: [200, 'العنوان لا يمكن أن يزيد عن 200 حرف']
  },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  if (this.password.length < 8) {
    return next(new Error('كلمة المرور يجب أن تكون 8 أحرف على الأقل'));
  }
  
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword) {
  if (this.lockUntil && this.lockUntil > Date.now()) {
    throw new Error('الحساب مغلق مؤقتاً بسبب محاولات تسجيل دخول فاشلة');
  }
  
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  
  if (!isMatch) {
    this.loginAttempts += 1;
    if (this.loginAttempts >= 5) {
      this.lockUntil = Date.now() + 30 * 60 * 1000; // 30 دقيقة
    }
    await this.save();
    return false;
  }
  
  if (this.loginAttempts > 0) {
    this.loginAttempts = 0;
    this.lockUntil = undefined;
    await this.save();
  }
  
  return true;
};

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'اسم المنتج مطلوب'],
    trim: true,
    minlength: [2, 'اسم المنتج يجب أن يكون على الأقل حرفين'],
    maxlength: [100, 'اسم المنتج لا يمكن أن يزيد عن 100 حرف']
  },
  description: {
    type: String,
    required: [true, 'وصف المنتج مطلوب'],
    minlength: [10, 'الوصف يجب أن يكون على الأقل 10 أحرف'],
    maxlength: [1000, 'الوصف لا يمكن أن يزيد عن 1000 حرف']
  },
  price: {
    type: Number,
    required: [true, 'سعر المنتج مطلوب'],
    min: [0, 'السعر لا يمكن أن يكون سالب'],
    max: [100000, 'السعر لا يمكن أن يزيد عن 100,000']
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
    min: [0, 'الكمية لا يمكن أن تكون سالبة'],
    max: [100000, 'الكمية لا يمكن أن تزيد عن 100,000']
  },
  supplier: {
    type: String,
    required: [true, 'المورد مطلوب'],
    trim: true
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

const orderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  products: [{
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    name: {
      type: String,
      required: true
    },
    price: {
      type: Number,
      required: true,
      min: 0
    },
    quantity: {
      type: Number,
      required: true,
      min: 1,
      max: 1000
    }
  }],
  totalAmount: {
    type: Number,
    required: true,
    min: 0
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  shippingAddress: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  phone: {
    type: String,
    required: true,
    match: [/^[0-9]{10}$/, 'رقم الجوال يجب أن يكون 10 أرقام']
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'bank_transfer'],
    default: 'cash'
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'failed', 'refunded'],
    default: 'pending'
  }
}, {
  timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

// 🔑 إنشاء JWT token آمن
const signToken = (id, role) => {
  const expiresIn = role === 'admin' ? '1h' : '7d';
  
  return jwt.sign(
    { id, role }, 
    process.env.JWT_SECRET,
    { expiresIn }
  );
};

// 🛡️ middleware للتحقق من التوكن
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

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

// 🛡️ middleware للمسؤولين فقط
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'ليس لديك صلاحية للقيام بهذا الإجراء'
      });
    }
    next();
  };
};

// 🧹 معالج الأخطاء
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'بيانات غير صالحة',
      errors: errors.array()
    });
  }
  next();
};

// 📊 إضافة بيانات تجريبية
const addSampleProducts = async () => {
  try {
    const productsCount = await Product.countDocuments();
    
    if (productsCount === 0) {
      await Product.create([
        {
          name: 'أسمنت أبيض',
          description: 'أسمنت أبيض عالي الجودة للمباني والدهانات',
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
        }
      ]);
      console.log('✅ تم إضافة المنتجات التجريبية');
    }
  } catch (error) {
    console.log('❌ خطأ في إضافة المنتجات التجريبية');
  }
};

addSampleProducts();

// 🎯 الـ APIs

// الصفحة الرئيسية
app.get('/', (req, res) => {
  res.json({ 
    message: 'بناء مارت - Backend شغال!',
    status: 'نجاح',
    version: '3.0.0',
    security: 'مؤمن'
  });
});

// 🔐 APIs المصادقة
app.post('/api/auth/register', 
  [
    body('name').isLength({ min: 2, max: 50 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('phone').optional().isLength({ min: 10, max: 10 }).isNumeric(),
    body('address').optional().isLength({ max: 200 }).trim().escape()
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { name, email, password, phone, address } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'البريد الإلكتروني مسجل مسبقاً'
        });
      }

      const newUser = await User.create({
        name: name.trim(),
        email: email.toLowerCase().trim(),
        password,
        phone: phone ? phone.trim() : undefined,
        address: address ? address.trim() : undefined
      });

      const token = signToken(newUser._id, newUser.role);

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
        message: 'خطأ في السيرفر'
      });
    }
  }
);

app.post('/api/auth/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 1 })
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password +loginAttempts +lockUntil');
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
        });
      }

      const isPasswordCorrect = await user.correctPassword(password);
      
      if (!isPasswordCorrect) {
        return res.status(401).json({
          success: false,
          message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
        });
      }

      const token = signToken(user._id, user.role);

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
      if (error.message.includes('مغلق مؤقتاً')) {
        return res.status(423).json({
          success: false,
          message: error.message
        });
      }
      
      res.status(500).json({
        success: false,
        message: 'خطأ في السيرفر'
      });
    }
  }
);

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

// 🛍️ APIs المنتجات
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
      message: 'خطأ في جلب المنتجات'
    });
  }
});

app.get('/api/products/search', async (req, res) => {
  try {
    const { q, category, minPrice, maxPrice } = req.query;
    
    let filter = { isActive: true };
    
    if (q && typeof q === 'string') {
      filter.name = { $regex: q.trim(), $options: 'i' };
    }
    
    if (category && ['مواد أساسية', 'مواد بناء', 'ادوات كهربائية', 'ادوات صحية'].includes(category)) {
      filter.category = category;
    }
    
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice && !isNaN(minPrice)) filter.price.$gte = Number(minPrice);
      if (maxPrice && !isNaN(maxPrice)) filter.price.$lte = Number(maxPrice);
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
      message: 'خطأ في البحث'
    });
  }
});

app.post('/api/products', protect, restrictTo('admin'),
  [
    body('name').isLength({ min: 2, max: 100 }).trim().escape(),
    body('description').isLength({ min: 10, max: 1000 }).trim().escape(),
    body('price').isFloat({ min: 0, max: 100000 }),
    body('category').isIn(['مواد أساسية', 'مواد بناء', 'ادوات كهربائية', 'ادوات صحية']),
    body('stock').isInt({ min: 0, max: 100000 }),
    body('supplier').isLength({ min: 2, max: 100 }).trim().escape(),
    body('unit').isIn(['كيلو', 'طن', 'متر', 'علبة', 'كيس'])
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const product = await Product.create(req.body);
      
      res.status(201).json({
        success: true,
        message: 'تم إضافة المنتج بنجاح',
        product
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'خطأ في إضافة المنتج'
      });
    }
  }
);

// 📦 APIs الطلبات
app.post('/api/orders', protect,
  [
    body('products').isArray({ min: 1 }),
    body('products.*.productId').isMongoId(),
    body('products.*.name').isLength({ min: 2, max: 100 }).trim().escape(),
    body('products.*.price').isFloat({ min: 0 }),
    body('products.*.quantity').isInt({ min: 1, max: 1000 }),
    body('totalAmount').isFloat({ min: 0 }),
    body('shippingAddress').isLength({ min: 5, max: 200 }).trim().escape(),
    body('phone').isLength({ min: 10, max: 10 }).isNumeric()
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { products, totalAmount, shippingAddress, phone, paymentMethod } = req.body;

      // التحقق من توفر المنتجات
      for (const item of products) {
        const product = await Product.findById(item.productId);
        if (!product || product.stock < item.quantity) {
          return res.status(400).json({
            success: false,
            message: `المنتج ${item.name} غير متوفر بالكمية المطلوبة`
          });
        }
      }

      // خصم الكمية من المخزون
      for (const item of products) {
        await Product.findByIdAndUpdate(
          item.productId, 
          { $inc: { stock: -item.quantity } }
        );
      }

      const newOrder = await Order.create({
        user: req.user._id,
        products,
        totalAmount,
        shippingAddress: shippingAddress.trim(),
        phone: phone.trim(),
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
        message: 'خطأ في إنشاء الطلب'
      });
    }
  }
);

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
      message: 'خطأ في جلب الطلبات'
    });
  }
});

app.get('/api/orders/:id', protect, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('user', 'name email phone');

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'الطلب غير موجود'
      });
    }

    if (order.user._id.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'غير مصرح بالوصول لهذا الطلب'
      });
    }

    res.status(200).json({
      success: true,
      order
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الطلب'
    });
  }
});

// 💳 APIs الدفع
app.post('/api/payment/create', protect,
  [
    body('orderId').isMongoId(),
    body('amount').isFloat({ min: 0 }),
    body('paymentMethod').isIn(['cash', 'card', 'bank_transfer'])
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { orderId, amount, paymentMethod } = req.body;

      const order = await Order.findById(orderId);
      if (!order) {
        return res.status(404).json({
          success: false,
          message: 'الطلب غير موجود'
        });
      }

      if (order.user.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'غير مصرح بالدفع لهذا الطلب'
        });
      }

      // محاكاة إنشاء جلسة دفع آمنة
      const paymentData = {
        paymentId: 'pay_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
        orderId,
        amount,
        paymentMethod: paymentMethod || 'card',
        status: 'pending',
        paymentUrl: `https://payment-gateway.com/pay/${Date.now()}`,
        createdAt: new Date()
      };

      res.status(200).json({
        success: true,
        message: 'تم إنشاء جلسة الدفع',
        payment: paymentData
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'خطأ في إنشاء الدفع'
      });
    }
  }
);

app.post('/api/payment/verify', protect,
  [
    body('paymentId').isLength({ min: 10 }),
    body('orderId').isMongoId()
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { paymentId, orderId } = req.body;

      const order = await Order.findById(orderId);
      if (!order) {
        return res.status(404).json({
          success: false,
          message: 'الطلب غير موجود'
        });
      }

      if (order.user.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'غير مصرح بالتحقق من هذا الطلب'
        });
      }

      // محاكاة التحقق من الدفع بشكل آمن
      const isSuccess = require('crypto').randomBytes(1)[0] > 51; // 80% نجاح

      if (isSuccess) {
        await Order.findByIdAndUpdate(orderId, {
          status: 'confirmed',
          paymentStatus: 'paid'
        });

        res.status(200).json({
          success: true,
          message: 'تم الدفع بنجاح',
          payment: {
            paymentId,
            status: 'paid',
            paidAt: new Date()
          }
        });
      } else {
        await Order.findByIdAndUpdate(orderId, {
          paymentStatus: 'failed'
        });

        res.status(400).json({
          success: false,
          message: 'فشل في عملية الدفع',
          payment: {
            paymentId,
            status: 'failed'
          }
        });
      }

    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'خطأ في التحقق من الدفع'
      });
    }
  }
);

// 🔔 APIs إضافية
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
      message: 'خطأ في جلب الإشعارات'
    });
  }
});

// 📊 APIs الإحصائيات (للمسؤول)
app.get('/api/admin/stats', protect, restrictTo('admin'), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalRevenue = await Order.aggregate([
      { $match: { status: { $in: ['confirmed', 'delivered'] } } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);

    const recentOrders = await Order.find()
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(5);

    res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        totalProducts, 
        totalOrders,
        totalRevenue: totalRevenue[0]?.total || 0,
        recentOrders
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب الإحصائيات'
    });
  }
});

// 🚨 معالج الأخطاء
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'الصفحة غير موجودة',
    path: req.path
  });
});

app.use((error, req, res, next) => {
  console.error('🚨 خطأ:', error);
  
  res.status(500).json({
    success: false,
    message: 'حدث خطأ غير متوقع في السيرفر'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ السيرفر شغال على http://localhost:${PORT}`);
  console.log(`🔒 الوضع: ${process.env.NODE_ENV || 'development'}`);
});