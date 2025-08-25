// mongo-init.js - MongoDB initialization script
// Place this file in your project root directory
// Run this script using: mongosh ecommerce < mongo-init.js

print("=== E-Commerce Database Initialization ===");

// Switch to ecommerce database
use ecommerce;

print("Creating collections and indexes...");

// Create users collection with unique indexes
db.createCollection("users");
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });

// Create products collection
db.createCollection("products");
db.products.createIndex({ "name": 1 });
db.products.createIndex({ "category": 1 });
db.products.createIndex({ "price": 1 });

// Create orders collection with user index
db.createCollection("orders");
db.orders.createIndex({ "userId": 1 });
db.orders.createIndex({ "createdAt": -1 });
db.orders.createIndex({ "status": 1 });

// Create carts collection with user index
db.createCollection("carts");
db.carts.createIndex({ "userId": 1 }, { unique: true });

// Create purchases collection (Assessment requirement)
db.createCollection("purchases");
db.purchases.createIndex({ "username": 1 });
db.purchases.createIndex({ "purchaseDate": 1 });
db.purchases.createIndex({ "status": 1 });

print("Inserting sample data...");

// Sample users (passwords are BCrypt hashed)
db.users.insertMany([
    {
        username: "admin",
        email: "admin@ecommerce.com",
        password: "$2a$10$7q3z0iJ5b6Ei8J0bH0H5EeR8qh9aB3r0aE3lq6gT7kLZP1QmBvI6e", // password: admin123
        roles: ["ADMIN"],
        name: "System Administrator",
        contactNumber: "+94771234567",
        country: "Sri Lanka",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        username: "testuser",
        email: "user@test.com",
        password: "$2a$10$8QGqN1nmv5uQvYHeH.l4uO0bKk8OlAyxYVgD9VjN4lC2YwoR8Ug8S", // password: user123
        roles: ["USER"],
        name: "Test User",
        contactNumber: "+94777654321",
        country: "Sri Lanka",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        username: "john.doe",
        email: "john.doe@example.com",
        password: "$2a$10$8QGqN1nmv5uQvYHeH.l4uO0bKk8OlAyxYVgD9VjN4lC2YwoR8Ug8S", // password: user123
        roles: ["USER"],
        name: "John Doe",
        contactNumber: "+94701234567",
        country: "Sri Lanka",
        createdAt: new Date(),
        updatedAt: new Date()
    }
]);

// Sample products
db.products.insertMany([
    {
        name: "Smartphone X100",
        description: "Latest flagship smartphone with advanced camera and 5G connectivity",
        price: NumberDecimal("75000.00"),
        availableQuantity: 50,
        category: "Electronics",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Wireless Headphones",
        description: "Premium noise-cancelling wireless headphones with 30-hour battery life",
        price: NumberDecimal("15000.00"),
        availableQuantity: 100,
        category: "Audio",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Laptop Pro 15",
        description: "High-performance laptop with Intel i7 processor and 16GB RAM",
        price: NumberDecimal("125000.00"),
        availableQuantity: 25,
        category: "Computers",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Tablet Air 11",
        description: "Lightweight tablet with 11-inch display and all-day battery",
        price: NumberDecimal("65000.00"),
        availableQuantity: 40,
        category: "Electronics",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Smart Watch Series 5",
        description: "Advanced fitness tracking and health monitoring smartwatch",
        price: NumberDecimal("35000.00"),
        availableQuantity: 75,
        category: "Wearables",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Bluetooth Speaker",
        description: "Portable waterproof speaker with 360-degree sound",
        price: NumberDecimal("8500.00"),
        availableQuantity: 80,
        category: "Audio",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Gaming Console X",
        description: "Next-generation gaming console with 4K gaming support",
        price: NumberDecimal("85000.00"),
        availableQuantity: 20,
        category: "Gaming",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Digital Camera 4K",
        description: "Professional mirrorless camera with 4K video recording",
        price: NumberDecimal("95000.00"),
        availableQuantity: 15,
        category: "Photography",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Power Bank 20000mAh",
        description: "High-capacity portable charger with fast charging support",
        price: NumberDecimal("4500.00"),
        availableQuantity: 120,
        category: "Accessories",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        name: "Wireless Charger Pad",
        description: "Qi-compatible wireless charging pad for all devices",
        price: NumberDecimal("3500.00"),
        availableQuantity: 90,
        category: "Accessories",
        createdAt: new Date(),
        updatedAt: new Date()
    }
]);

// Sample purchases (Assessment requirement)
db.purchases.insertMany([
    {
        username: "testuser",
        purchaseDate: new Date("2024-12-25"),
        deliveryTime: "10AM",
        deliveryLocation: "Colombo",
        productName: "Smartphone X100",
        quantity: 1,
        message: "Please handle with care",
        status: "PENDING",
        createdAt: new Date(),
        updatedAt: new Date()
    },
    {
        username: "john.doe",
        purchaseDate: new Date("2024-12-26"),
        deliveryTime: "12PM",
        deliveryLocation: "Kandy",
        productName: "Wireless Headphones",
        quantity: 2,
        message: "Gift wrapping requested",
        status: "CONFIRMED",
        createdAt: new Date(),
        updatedAt: new Date()
    }
]);

print("Database initialization completed successfully!");
print("Collections created: users, products, orders, carts, purchases");
print("Sample data inserted:");
print("  - Users: " + db.users.countDocuments());
print("  - Products: " + db.products.countDocuments());
print("  - Purchases: " + db.purchases.countDocuments());

// Verify the setup
print("\n=== Verification ===");
print("Database: " + db.getName());
print("Collections: " + db.getCollectionNames());

// Display indexes for each collection
print("\n=== Collection Indexes ===");
db.getCollectionNames().forEach(function(collectionName) {
    print(collectionName + " indexes:");
    db.getCollection(collectionName).getIndexes().forEach(function(index) {
        print("  - " + JSON.stringify(index.key));
    });
});

print("\n=== Setup Complete ===");
print("You can now start your Spring Boot application!");
print("Default users created:");
print("  - admin/admin123 (ADMIN role)");
print("  - testuser/user123 (USER role)");
print("  - john.doe/user123 (USER role)");