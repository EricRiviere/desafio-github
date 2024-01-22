import { Router } from "express";
import productsDao from "../dao/mdbManagers/products.dao.js";
import cartsDao from "../dao/mdbManagers/carts.dao.js";
import userModel from "../dao/models/user.model.js";

const viewsRouter = Router();

// Middleware de autorización
const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    return next();
  } else {
    res.status(403).send("Access forbiden. Your role must be 'admin'.");
  }
};

//Product Manager
viewsRouter.get("/productManager", isAdmin, async (req, res) => {
  const products = await productsDao.getAllProducts();
  res.render("productManager", {
    title: "Products Mongoose",
    products,
  });
});

//Chat
viewsRouter.get("/chat", (req, res) => {
  res.render("chat", {
    title: "Chat",
  });
});

//Products
viewsRouter.get("/products", async (req, res) => {
  const { page, limit, sort } = req.query;
  const products = await productsDao.getAllProducts(page, limit, sort);

  res.render("products", {
    title: "Products",
    products,
    user: req.session.user,
  });
});

//Carts
viewsRouter.get("/carts/", async (req, res) => {
  const carts = await cartsDao.getAllCarts();
  res.render("carts", {
    title: "Carts",
    carts,
  });
});

//Cart
viewsRouter.get("/carts/:cid", async (req, res) => {
  const { cid } = req.params;
  const cart = await cartsDao.getCartById(cid);
  res.render("cart", {
    title: "Cart",
    cart,
  });
});

viewsRouter.get("/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      res.json({ error: "Error logout", msg: "Error al cerrar la session" });
    }
    res.send("Session cerrada correctamente!");
  });
});

export { viewsRouter };
