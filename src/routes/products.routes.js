import { Router } from "express";
import productsDao from "../dao/mdbManagers/products.dao.js";

const ProductRouter = Router();

ProductRouter.get("/", async (req, res) => {
  try {
    const { limit = 10, page = 1, sort } = req.query;

    const products = await productsDao.getAllProducts(page, limit, sort);

    res.json(products);
  } catch (error) {
    res.status(400).json(error);
  }
});

ProductRouter.get("/:pid", async (req, res) => {
  try {
    const pid = req.params.pid;
    const response = await productsDao.getProductById(pid);
    if (!response) return res.send("No product found");
    res.json({
      message: "success",
      response,
    });
  } catch (error) {
    res.json(error);
  }
});

ProductRouter.post("/", async (req, res) => {
  try {
    const product = req.body;
    await productsDao.createProduct(product);
    res.redirect("/productManager");
  } catch (error) {
    res.json(error);
  }
});

ProductRouter.put("/:pid", async (req, res) => {
  try {
    const pid = req.params.pid;
    const product = req.body;
    const response = await productsDao.updateProduct(pid, product);
    if (!response) return res.send("Product not found");
    res.json({
      message: "success",
      response,
    });
  } catch (error) {
    res.json(error);
  }
});

ProductRouter.delete("/:pid", async (req, res) => {
  try {
    const pid = req.params.pid;
    const response = await productsDao.deleteProduct(pid);
    if (!response) return res.send("Product not found");
    res.json({
      message: "Product deleted",
      response,
    });
  } catch (error) {
    res.json(error);
  }
});

export { ProductRouter };
