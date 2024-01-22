import { productModel } from "../models/product.model.js";

class ProductDao {
  async getAllProducts(page, limit, sort) {
    try {
      const options = {
        page: parseInt(page) || 1,
        limit: parseInt(limit) || 10,
      };

      if (sort !== undefined) {
        options.sort = { price: parseInt(sort) };
      }

      const response = await productModel.paginate({}, options);

      return response;
    } catch (error) {
      throw new Error("Error fetching products: " + error.message);
    }
  }

  async getProductById(id) {
    let product = await productModel.findById(id);
    if (!product) {
      throw new Error("Product not found");
    } else {
      return product;
    }
  }

  async createProduct(product) {
    return await productModel.create(product);
  }

  async updateProduct(id, product) {
    return await productModel.findByIdAndUpdate(id, product);
  }

  async deleteProduct(id) {
    return await productModel.findByIdAndDelete(id);
  }
}

export default new ProductDao();
