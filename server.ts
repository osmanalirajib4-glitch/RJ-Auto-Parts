import express, { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { 
  AdminUser, 
  BannerSlide, 
  Category, 
  Customer, 
  DashboardStats, 
  Order, 
  Product, 
  WebsiteSettings 
} from './src/types';
import { 
  INITIAL_ADMIN_USER, 
  INITIAL_BANNER_SLIDES, 
  INITIAL_CATEGORIES, 
  INITIAL_CUSTOMERS, 
  INITIAL_ORDERS, 
  INITIAL_PRODUCTS, 
  INITIAL_WEBSITE_SETTINGS 
} from './src/data/dbSeed';

// Secure Password Hashing & Verification Utilities
export function hashPassword(password: string, salt?: string): string {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, s, 10000, 64, 'sha512').toString('hex');
  return `${s}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  if (!password || !storedHash) return false;
  if (storedHash.includes(':')) {
    const [salt, originalHash] = storedHash.split(':');
    const hashToVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    try {
      return crypto.timingSafeEqual(Buffer.from(hashToVerify, 'hex'), Buffer.from(originalHash, 'hex'));
    } catch {
      return false;
    }
  }
  return storedHash === password;
}

// Default Final Active Admin Credentials (rajib51 / Osman9900@)
const DEFAULT_ADMIN_USERNAME = 'rajib51';
const DEFAULT_ADMIN_PASSWORD = 'Osman9900@';

interface DatabaseSchema {
  settings: WebsiteSettings;
  categories: Category[];
  products: Product[];
  banners: BannerSlide[];
  orders: Order[];
  customers: Customer[];
  admin: AdminUser;
  adminCredentials: {
    username: string;
    passwordHash: string;
  };
}

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const UPLOADS_DIR = path.join(process.cwd(), 'public', 'uploads');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Read database
function readDb(): DatabaseSchema {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      const parsed = JSON.parse(data);

      let credentials = parsed.adminCredentials;
      // Auto-migrate if legacy username or outdated hash is detected
      if (!credentials || credentials.username !== DEFAULT_ADMIN_USERNAME || !verifyPassword(DEFAULT_ADMIN_PASSWORD, credentials.passwordHash)) {
        credentials = {
          username: DEFAULT_ADMIN_USERNAME,
          passwordHash: hashPassword(DEFAULT_ADMIN_PASSWORD)
        };
      }

      let adminObj = parsed.admin;
      if (!adminObj || adminObj.username !== DEFAULT_ADMIN_USERNAME) {
        adminObj = {
          ...INITIAL_ADMIN_USER,
          username: DEFAULT_ADMIN_USERNAME,
          name: adminObj?.name || 'Osman Ali Rajib',
          email: adminObj?.email || 'osmanalirajib4@gmail.com'
        };
      }

      const dbObj: DatabaseSchema = {
        settings: parsed.settings || INITIAL_WEBSITE_SETTINGS,
        categories: parsed.categories || INITIAL_CATEGORIES,
        products: parsed.products || INITIAL_PRODUCTS,
        banners: parsed.banners || parsed.bannerSlides || INITIAL_BANNER_SLIDES,
        orders: parsed.orders || INITIAL_ORDERS,
        customers: parsed.customers || INITIAL_CUSTOMERS,
        admin: adminObj,
        adminCredentials: credentials
      };

      // Persist migrated schema if changes occurred
      if (parsed.adminCredentials?.username !== DEFAULT_ADMIN_USERNAME || !verifyPassword(DEFAULT_ADMIN_PASSWORD, parsed.adminCredentials?.passwordHash)) {
        writeDb(dbObj);
      }

      return dbObj;
    }
  } catch (err) {
    console.error('Error reading db.json, returning default seed:', err);
  }

  const initialDb: DatabaseSchema = {
    settings: INITIAL_WEBSITE_SETTINGS,
    categories: INITIAL_CATEGORIES,
    products: INITIAL_PRODUCTS,
    banners: INITIAL_BANNER_SLIDES,
    orders: INITIAL_ORDERS,
    customers: INITIAL_CUSTOMERS,
    admin: INITIAL_ADMIN_USER,
    adminCredentials: {
      username: DEFAULT_ADMIN_USERNAME,
      passwordHash: hashPassword(DEFAULT_ADMIN_PASSWORD)
    }
  };
  writeDb(initialDb);
  return initialDb;
}

// Write database atomically
function writeDb(data: DatabaseSchema): void {
  try {
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Failed to write db.json:', err);
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // JSON Body Parser with 50MB payload limit for image uploads
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Static uploads directory serving
  app.use('/uploads', express.static(UPLOADS_DIR));

  // Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
  });

  // ==========================================
  // 1. AUTHENTICATION & ADMIN PROFILE
  // ==========================================
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    const db = readDb();

    const cleanUser = (username || '').trim().toLowerCase();
    const cleanPass = (password || '').trim();

    // Verify username matches only the active rajib51 account
    const storedUsername = (db.adminCredentials.username || DEFAULT_ADMIN_USERNAME).toLowerCase();

    if (cleanUser === storedUsername) {
      const isPasswordValid = verifyPassword(cleanPass, db.adminCredentials.passwordHash) || cleanPass === DEFAULT_ADMIN_PASSWORD;

      if (isPasswordValid) {
        // Sync hash if needed
        if (!verifyPassword(cleanPass, db.adminCredentials.passwordHash)) {
          db.adminCredentials.passwordHash = hashPassword(cleanPass);
        }
        db.admin.lastLogin = new Date().toISOString();
        writeDb(db);

        const token = `rj_admin_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
        return res.json({
          success: true,
          token,
          admin: db.admin,
          message: 'Admin login successful'
        });
      }
    }

    return res.status(401).json({
      success: false,
      message: 'Invalid username or password. Please verify your admin credentials.'
    });
  });

  app.post('/api/auth/profile', (req: Request, res: Response) => {
    const { name, email, username, currentPassword, newPassword } = req.body;
    const db = readDb();

    if (newPassword) {
      if (!currentPassword || !verifyPassword(currentPassword.trim(), db.adminCredentials.passwordHash)) {
        return res.status(400).json({ success: false, message: 'Current password does not match.' });
      }
      db.adminCredentials.passwordHash = hashPassword(newPassword.trim());
    }

    if (username && username.trim()) {
      db.adminCredentials.username = username.trim();
      db.admin.username = username.trim();
    }
    if (name) db.admin.name = name.trim();
    if (email) db.admin.email = email.trim();

    writeDb(db);
    res.json({ success: true, admin: db.admin, message: 'Admin profile updated successfully.' });
  });

  // ==========================================
  // 2. WEBSITE SETTINGS
  // ==========================================
  app.get('/api/settings', (req: Request, res: Response) => {
    const db = readDb();
    res.json({ success: true, settings: db.settings });
  });

  app.put('/api/settings', (req: Request, res: Response) => {
    const db = readDb();
    db.settings = { ...db.settings, ...req.body };
    writeDb(db);
    res.json({ success: true, settings: db.settings, message: 'Website settings updated successfully.' });
  });

  // ==========================================
  // 3. CATEGORIES
  // ==========================================
  app.get('/api/categories', (req: Request, res: Response) => {
    const db = readDb();
    res.json({ success: true, categories: db.categories });
  });

  app.post('/api/categories', (req: Request, res: Response) => {
    const { name, slug, description, image, iconName, color, isActive } = req.body;
    if (!name) {
      return res.status(400).json({ success: false, message: 'Category name is required.' });
    }

    const db = readDb();
    const newCategory: Category = {
      id: 'cat-' + Date.now(),
      name: name.trim(),
      slug: slug ? slug.trim().toLowerCase().replace(/\s+/g, '-') : name.toLowerCase().replace(/[^a-z0-9]/g, '-'),
      description: description?.trim() || '',
      image: image?.trim() || 'https://images.unsplash.com/photo-1486006920555-c77dce18193b?auto=format&fit=crop&w=600&q=80',
      iconName: iconName || 'Settings',
      color: color || 'from-amber-500/20 to-orange-500/10',
      itemCount: 0,
      isActive: isActive !== false
    };

    db.categories.unshift(newCategory);
    writeDb(db);
    res.json({ success: true, category: newCategory, message: 'Category created successfully.' });
  });

  app.put('/api/categories/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    const index = db.categories.findIndex(c => c.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Category not found.' });
    }

    db.categories[index] = { ...db.categories[index], ...req.body };
    writeDb(db);
    res.json({ success: true, category: db.categories[index], message: 'Category updated successfully.' });
  });

  app.delete('/api/categories/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    db.categories = db.categories.filter(c => c.id !== id);
    writeDb(db);
    res.json({ success: true, message: 'Category deleted successfully.' });
  });

  // ==========================================
  // 4. PRODUCTS (CRUD + DUPLICATE)
  // ==========================================
  app.get('/api/products', (req: Request, res: Response) => {
    const db = readDb();
    let products = [...db.products];

    const { category, search, stock, featured, sort } = req.query;

    if (category && category !== 'All') {
      products = products.filter(p => p.category === category);
    }
    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      products = products.filter(p => 
        p.name.toLowerCase().includes(q) ||
        p.description?.toLowerCase().includes(q) ||
        p.brand?.toLowerCase().includes(q) ||
        p.sku?.toLowerCase().includes(q)
      );
    }
    if (stock === 'inStock') {
      products = products.filter(p => (p.stockCount ?? 0) > 0 && p.inStock !== false);
    } else if (stock === 'outOfStock') {
      products = products.filter(p => (p.stockCount ?? 0) <= 0 || p.inStock === false);
    } else if (stock === 'lowStock') {
      products = products.filter(p => (p.stockCount ?? 0) > 0 && (p.stockCount ?? 0) <= 10);
    }

    if (featured === 'true') {
      products = products.filter(p => p.isFeatured);
    }

    // Sorting
    if (sort === 'price-low') {
      products.sort((a, b) => (a.price || 0) - (b.price || 0));
    } else if (sort === 'price-high') {
      products.sort((a, b) => (b.price || 0) - (a.price || 0));
    } else if (sort === 'rating') {
      products.sort((a, b) => (b.rating || 0) - (a.rating || 0));
    } else if (sort === 'newest') {
      products.sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
    }

    res.json({ success: true, count: products.length, products });
  });

  app.post('/api/products', (req: Request, res: Response) => {
    const db = readDb();
    const data = req.body;

    if (!data.name || !data.name.trim()) {
      return res.status(400).json({ success: false, message: 'Product name is required.' });
    }

    const newProduct: Product = {
      id: 'prod-' + Date.now(),
      name: data.name.trim(),
      category: data.category?.trim() || 'Engine & Drivetrain',
      brand: data.brand?.trim() || 'RJ Auto',
      price: data.price !== undefined && data.price !== null ? Number(data.price) : 1000,
      originalPrice: data.originalPrice ? Number(data.originalPrice) : undefined,
      rating: data.rating ? Number(data.rating) : 5.0,
      reviewCount: data.reviewCount ? Number(data.reviewCount) : 0,
      image: data.image?.trim() || 'https://images.unsplash.com/photo-1486006920555-c77dce18193b?auto=format&fit=crop&w=800&q=80',
      additionalImages: Array.isArray(data.additionalImages) ? data.additionalImages : [],
      description: data.description?.trim() || 'High performance automotive genuine part.',
      fullDescription: data.fullDescription?.trim() || data.description?.trim() || 'Guaranteed fitment and warranty.',
      unit: data.unit?.trim() || '1 Unit',
      badge: data.badge || (data.isBestSeller ? 'Best Seller' : data.isNew ? 'New' : undefined),
      inStock: data.stockCount !== undefined ? Number(data.stockCount) > 0 : data.inStock !== false,
      stockCount: data.stockCount !== undefined ? Number(data.stockCount) : 25,
      sku: data.sku?.trim() || `RJ-SKU-${Math.floor(1000 + Math.random() * 9000)}`,
      isFeatured: Boolean(data.isFeatured),
      isNew: Boolean(data.isNew),
      isBestSeller: Boolean(data.isBestSeller),
      isActive: data.isActive !== false,
      features: Array.isArray(data.features) && data.features.length > 0 ? data.features : [
        '100% Genuine Certified Quality',
        'Direct Fitment Guarantee for specified models',
        'Fast delivery across Bangladesh from Jashore'
      ],
      nutritionOrSpecs: typeof data.nutritionOrSpecs === 'object' ? data.nutritionOrSpecs : {
        'Brand': data.brand || 'RJ Auto',
        'Fitment': 'Universal / Model specific',
        'Warranty': 'Official Store Warranty'
      },
      tags: Array.isArray(data.tags) ? data.tags : ['Auto Parts', 'Genuine', 'RJ Auto'],
      reviews: [],
      clicksCount: 0,
      buyNowClicks: 0,
      directCartClicks: 0,
      lastClickedDate: null,
      createdAt: new Date().toISOString().split('T')[0]
    };

    db.products.unshift(newProduct);
    writeDb(db);
    res.json({ success: true, product: newProduct, message: 'Product created successfully.' });
  });

  app.put('/api/products/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    const index = db.products.findIndex(p => p.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Product not found.' });
    }

    const current = db.products[index];
    const data = req.body;

    const stockCount = data.stockCount !== undefined ? Number(data.stockCount) : current.stockCount ?? 20;
    const inStock = stockCount > 0 && data.inStock !== false;

    db.products[index] = {
      ...current,
      ...data,
      price: data.price !== undefined ? (data.price === null ? undefined : Number(data.price)) : current.price,
      originalPrice: data.originalPrice !== undefined ? (data.originalPrice === null ? undefined : Number(data.originalPrice)) : current.originalPrice,
      stockCount,
      inStock,
      updatedAt: new Date().toISOString()
    };

    writeDb(db);
    res.json({ success: true, product: db.products[index], message: 'Product updated successfully.' });
  });

  app.post('/api/products/:id/duplicate', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    const original = db.products.find(p => p.id === id);

    if (!original) {
      return res.status(404).json({ success: false, message: 'Product not found.' });
    }

    const duplicated: Product = {
      ...original,
      id: 'prod-' + Date.now(),
      name: `${original.name} (Copy)`,
      sku: `${original.sku || 'SKU'}-COPY`,
      clicksCount: 0,
      buyNowClicks: 0,
      directCartClicks: 0,
      createdAt: new Date().toISOString().split('T')[0]
    };

    db.products.unshift(duplicated);
    writeDb(db);
    res.json({ success: true, product: duplicated, message: 'Product duplicated successfully.' });
  });

  app.delete('/api/products/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    db.products = db.products.filter(p => p.id !== id);
    writeDb(db);
    res.json({ success: true, message: 'Product deleted successfully.' });
  });

  // ==========================================
  // 5. INVENTORY MANAGEMENT
  // ==========================================
  app.get('/api/inventory', (req: Request, res: Response) => {
    const db = readDb();
    const inventory = db.products.map(p => ({
      id: p.id,
      name: p.name,
      sku: p.sku || 'N/A',
      category: p.category,
      brand: p.brand || 'RJ Auto',
      price: p.price,
      stockCount: p.stockCount ?? 0,
      inStock: (p.stockCount ?? 0) > 0 && p.inStock !== false,
      image: p.image
    }));
    res.json({ success: true, inventory });
  });

  app.put('/api/inventory/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const { stockCount, inStock } = req.body;
    const db = readDb();
    const index = db.products.findIndex(p => p.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Product not found.' });
    }

    const count = Number(stockCount);
    db.products[index].stockCount = count;
    db.products[index].inStock = inStock !== undefined ? inStock : count > 0;
    db.products[index].updatedAt = new Date().toISOString();

    writeDb(db);
    res.json({ success: true, product: db.products[index], message: 'Stock updated successfully.' });
  });

  // ==========================================
  // 6. ORDERS MANAGEMENT
  // ==========================================
  app.get('/api/orders', (req: Request, res: Response) => {
    const db = readDb();
    const { status, search } = req.query;
    let orders = [...db.orders];

    if (status && status !== 'All') {
      orders = orders.filter(o => o.status === status);
    }
    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      orders = orders.filter(o =>
        o.id.toLowerCase().includes(q) ||
        o.customer.firstName.toLowerCase().includes(q) ||
        o.customer.lastName.toLowerCase().includes(q) ||
        o.customer.phone.includes(q) ||
        o.customer.email.toLowerCase().includes(q)
      );
    }

    res.json({ success: true, count: orders.length, orders });
  });

  app.post('/api/orders', (req: Request, res: Response) => {
    const db = readDb();
    const orderData: Partial<Order> = req.body;

    if (!orderData.items || orderData.items.length === 0) {
      return res.status(400).json({ success: false, message: 'Cart items cannot be empty.' });
    }
    if (!orderData.customer || !orderData.customer.phone) {
      return res.status(400).json({ success: false, message: 'Customer contact phone is required.' });
    }

    const newOrderId = 'RJ-' + Math.floor(100000 + Math.random() * 900000);
    const nowIso = new Date().toISOString();

    const newOrder: Order = {
      id: newOrderId,
      date: new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }),
      items: orderData.items,
      subtotal: orderData.subtotal || 0,
      discount: orderData.discount || 0,
      shipping: orderData.shipping || 0,
      tax: orderData.tax || 0,
      total: orderData.total || 0,
      customer: orderData.customer,
      status: 'Pending',
      paymentStatus: orderData.paymentStatus || (
        orderData.customer.paymentMethod === 'bkash'
          ? 'Paid (bKash)'
          : orderData.customer.paymentMethod === 'nagad'
          ? 'Paid (Nagad)'
          : orderData.customer.paymentMethod === 'card'
          ? 'Paid (Card)'
          : 'Pending (COD)'
      ),
      trackingNumber: `RJ-TRK-${Math.floor(10000 + Math.random() * 90000)}`,
      adminNotes: 'New order received from customer website.',
      createdAt: nowIso
    };

    // 1. Decrement Stock for ordered products
    newOrder.items.forEach(item => {
      const pIdx = db.products.findIndex(p => p.id === item.product.id);
      if (pIdx > -1) {
        const currentStock = db.products[pIdx].stockCount ?? 10;
        const newStock = Math.max(0, currentStock - item.quantity);
        db.products[pIdx].stockCount = newStock;
        if (newStock === 0) {
          db.products[pIdx].inStock = false;
        }
      }
    });

    // 2. Add or Update Customer Record
    const fullName = `${newOrder.customer.firstName} ${newOrder.customer.lastName}`.trim();
    const existingCustIdx = db.customers.findIndex(c => 
      c.phone === newOrder.customer.phone || (newOrder.customer.email && c.email === newOrder.customer.email)
    );

    if (existingCustIdx > -1) {
      db.customers[existingCustIdx].totalOrders += 1;
      db.customers[existingCustIdx].totalSpent += newOrder.total;
      db.customers[existingCustIdx].lastOrderDate = new Date().toISOString().split('T')[0];
      db.customers[existingCustIdx].orderIds.push(newOrderId);
      db.customers[existingCustIdx].address = `${newOrder.customer.streetAddress}, ${newOrder.customer.city}`;
    } else {
      const newCustomer: Customer = {
        id: 'cust-' + Date.now(),
        name: fullName || 'Valued Customer',
        email: newOrder.customer.email,
        phone: newOrder.customer.phone,
        address: `${newOrder.customer.streetAddress}, ${newOrder.customer.city}`,
        city: newOrder.customer.city,
        postalCode: newOrder.customer.postalCode,
        totalOrders: 1,
        totalSpent: newOrder.total,
        lastOrderDate: new Date().toISOString().split('T')[0],
        orderIds: [newOrderId],
        createdAt: new Date().toISOString().split('T')[0]
      };
      db.customers.unshift(newCustomer);
    }

    db.orders.unshift(newOrder);
    writeDb(db);

    res.json({ success: true, order: newOrder, message: 'Order placed successfully!' });
  });

  app.put('/api/orders/:id/status', (req: Request, res: Response) => {
    const { id } = req.params;
    const { status, trackingNumber, adminNotes, paymentStatus } = req.body;
    const db = readDb();
    const index = db.orders.findIndex(o => o.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Order not found.' });
    }

    if (status) db.orders[index].status = status;
    if (trackingNumber !== undefined) db.orders[index].trackingNumber = trackingNumber;
    if (adminNotes !== undefined) db.orders[index].adminNotes = adminNotes;
    if (paymentStatus !== undefined) db.orders[index].paymentStatus = paymentStatus;

    writeDb(db);
    res.json({ success: true, order: db.orders[index], message: `Order marked as ${status || 'updated'}` });
  });

  app.delete('/api/orders/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    db.orders = db.orders.filter(o => o.id !== id);
    writeDb(db);
    res.json({ success: true, message: 'Order deleted successfully.' });
  });

  // ==========================================
  // 7. CUSTOMERS MANAGEMENT
  // ==========================================
  app.get('/api/customers', (req: Request, res: Response) => {
    const db = readDb();
    const { search } = req.query;
    let customers = [...db.customers];

    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      customers = customers.filter(c =>
        c.name.toLowerCase().includes(q) ||
        c.phone.includes(q) ||
        c.email.toLowerCase().includes(q) ||
        c.city.toLowerCase().includes(q)
      );
    }

    res.json({ success: true, count: customers.length, customers });
  });

  app.get('/api/customers/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    const customer = db.customers.find(c => c.id === id);

    if (!customer) {
      return res.status(404).json({ success: false, message: 'Customer not found.' });
    }

    const customerOrders = db.orders.filter(o => 
      customer.orderIds.includes(o.id) || o.customer.phone === customer.phone
    );

    res.json({ success: true, customer, orders: customerOrders });
  });

  // ==========================================
  // 8. BANNERS MANAGEMENT
  // ==========================================
  app.get('/api/banners', (req: Request, res: Response) => {
    const db = readDb();
    res.json({ success: true, banners: db.banners });
  });

  app.post('/api/banners', (req: Request, res: Response) => {
    const { title, highlight, description, ctaText, ctaLink, discountText, image, badge, badgeColor, isActive } = req.body;
    if (!title || !image) {
      return res.status(400).json({ success: false, message: 'Banner title and image are required.' });
    }

    const db = readDb();
    const newSlide: BannerSlide = {
      id: 'slide-' + Date.now(),
      badge: badge?.trim() || '🔥 Hot Deal',
      badgeColor: badgeColor || 'bg-red-500/20 text-red-300 border-red-400/30',
      title: title.trim(),
      highlight: highlight?.trim() || 'Exclusive RJ Auto Parts',
      description: description?.trim() || 'Top-rated parts with fast delivery across Bangladesh.',
      ctaText: ctaText?.trim() || 'Shop Now',
      ctaLink: ctaLink?.trim() || 'shop',
      discountText: discountText?.trim() || 'Best Price Guarantee',
      image: image.trim(),
      isActive: isActive !== false,
      order: db.banners.length + 1
    };

    db.banners.push(newSlide);
    writeDb(db);
    res.json({ success: true, banner: newSlide, message: 'Banner slide created successfully.' });
  });

  app.put('/api/banners/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    const index = db.banners.findIndex(b => b.id === id);

    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Banner not found.' });
    }

    db.banners[index] = { ...db.banners[index], ...req.body };
    writeDb(db);
    res.json({ success: true, banner: db.banners[index], message: 'Banner slide updated.' });
  });

  app.delete('/api/banners/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const db = readDb();
    db.banners = db.banners.filter(b => b.id !== id);
    writeDb(db);
    res.json({ success: true, message: 'Banner slide removed.' });
  });

  app.put('/api/banners/reorder', (req: Request, res: Response) => {
    const { banners } = req.body;
    if (!Array.isArray(banners)) {
      return res.status(400).json({ success: false, message: 'Banners array expected.' });
    }

    const db = readDb();
    db.banners = banners;
    writeDb(db);
    res.json({ success: true, banners: db.banners, message: 'Banners order saved.' });
  });

  // ==========================================
  // 9. DASHBOARD STATS
  // ==========================================
  app.get('/api/dashboard/stats', (req: Request, res: Response) => {
    const db = readDb();

    const totalSales = db.orders
      .filter(o => o.status !== 'Cancelled')
      .reduce((sum, o) => sum + (o.total || 0), 0);

    const stats: DashboardStats = {
      totalSales,
      totalOrders: db.orders.length,
      totalProducts: db.products.length,
      totalCategories: db.categories.length,
      totalCustomers: db.customers.length,
      pendingOrders: db.orders.filter(o => o.status === 'Pending').length,
      confirmedOrders: db.orders.filter(o => o.status === 'Confirmed').length,
      processingOrders: db.orders.filter(o => o.status === 'Processing').length,
      shippedOrders: db.orders.filter(o => o.status === 'Shipped').length,
      deliveredOrders: db.orders.filter(o => o.status === 'Delivered').length,
      cancelledOrders: db.orders.filter(o => o.status === 'Cancelled').length,
      lowStockProducts: db.products.filter(p => (p.stockCount ?? 0) > 0 && (p.stockCount ?? 0) <= 10).length,
      outOfStockProducts: db.products.filter(p => (p.stockCount ?? 0) <= 0 || p.inStock === false).length
    };

    const recentOrders = db.orders.slice(0, 8);
    const recentProducts = db.products.slice(0, 6);
    const lowStockList = db.products.filter(p => (p.stockCount ?? 0) <= 10);

    res.json({
      success: true,
      stats,
      recentOrders,
      recentProducts,
      lowStockList
    });
  });

  // ==========================================
  // 10. IMAGE UPLOAD HANDLER
  // ==========================================
  app.post('/api/upload', (req: Request, res: Response) => {
    const { imageBase64, filename, folder } = req.body;

    if (!imageBase64) {
      return res.status(400).json({ success: false, message: 'imageBase64 is required.' });
    }

    try {
      // Clean base64 string
      const matches = imageBase64.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
      let buffer: Buffer;
      let extension = 'png';

      if (matches && matches.length === 3) {
        const mimeType = matches[1];
        if (mimeType.includes('jpeg') || mimeType.includes('jpg')) extension = 'jpg';
        else if (mimeType.includes('webp')) extension = 'webp';
        else if (mimeType.includes('gif')) extension = 'gif';
        buffer = Buffer.from(matches[2], 'base64');
      } else {
        buffer = Buffer.from(imageBase64, 'base64');
      }

      const safeName = (filename || 'img').replace(/[^a-zA-Z0-9_-]/g, '_');
      const uniqueFileName = `${safeName}_${Date.now()}.${extension}`;
      const filePath = path.join(UPLOADS_DIR, uniqueFileName);

      fs.writeFileSync(filePath, buffer);

      const publicUrl = `/uploads/${uniqueFileName}`;
      res.json({
        success: true,
        url: publicUrl,
        filename: uniqueFileName,
        message: 'Image uploaded successfully.'
      });
    } catch (err: any) {
      console.error('Upload error:', err);
      // Fallback: If write fails for any reason, return the data URI directly
      res.json({
        success: true,
        url: imageBase64,
        message: 'Image cached in memory.'
      });
    }
  });

  // ==========================================
  // VITE / SPA PRODUCTION MIDDLEWARE
  // ==========================================
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`RJ Auto Parts Full-Stack Server running on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});
