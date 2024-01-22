import { cartModel } from "../models/cart.model.js";
import { productModel } from "../models/product.model.js";

class CartDao {
  async getAllCarts() {
    return await cartModel.find();
  }

  async getCartById(id) {
    let cart = await cartModel.findById(id);
    if (!cart) {
      throw new Error("Cart not found");
    } else {
      return cart;
    }
  }

  async createCart() {
    return await cartModel.create({});
  }

  async addProductToCart(cartId, productId) {
    const cart = await cartModel.findById(cartId);
    if (!cart) {
      throw new Error("Cart not found");
    }
    const product = await productModel.findById(productId);
    if (!product) {
      throw new Error("Product not found");
    }
    const existingProduct = cart.products.find((product) =>
      product.productId.equals(productId)
    );
    if (existingProduct) {
      existingProduct.quantity++;
    } else {
      cart.products.push({ productId: productId, quantity: 1 });
    }
    return await cart.save();
  }

  async deleteProductFromCart(cartId, productId) {
    const cart = await cartModel.findById(cartId);
    if (!cart) {
      throw new Error("Cart not found");
    }
    const product = await productModel.findById(productId);
    if (!product) {
      throw new Error("Product not found");
    }
    const productIndex = cart.products.findIndex(
      (product) => product.productId.toString() === productId
    );
    if (productIndex === -1) {
      throw new Error("Product not found in the cart");
    }
    cart.products.splice(productIndex, 1);
    await cart.save();
    return cart;
  }

  async updateCart(cartId, newProducts) {
    const cart = await cartModel.findById(cartId);
    if (!cart) {
      throw new Error("Cart not found");
    }
    cart.products = newProducts;
    await cart.save();
    return cart;
  }

  async updateProductQuantity(cartId, productId, quantity) {
    const cart = await cartModel.findById(cartId);
    if (!cart) {
      throw new Error("Cart not found");
    }
    const product = await productModel.findById(productId);
    if (!product) {
      throw new Error("Product not found");
    }
    const existingProduct = cart.products.find((product) =>
      product.productId.equals(productId)
    );
    if (existingProduct) {
      existingProduct.quantity = quantity;
    } else {
      throw new Error("Product not found on cart");
    }
    return await cart.save();
  }

  async deleteCart(id) {
    let cart = await cartModel.findByIdAndDelete(id);
    if (!cart) {
      throw new Error("Cart not found");
    }
  }
}

export default new CartDao();
