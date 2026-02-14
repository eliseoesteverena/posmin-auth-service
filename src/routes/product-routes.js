/**
 * Product Routes Handler
 * HTTP layer - translates HTTP requests to service calls
 */

import { ProductError } from '../core/product-service.js';

export class ProductRoutes {
  constructor(productService) {
    this.productService = productService;
  }

  async handleCreateProduct(request, context) {
    let body;
    
    try {
      body = await request.json();
    } catch (error) {
      return this._errorResponse('Invalid JSON in request body', 400);
    }

    try {
      const product = await this.productService.createProduct(body, context);
      return this._successResponse(product, 201);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleGetProduct(request, productId, context) {
    try {
      const product = await this.productService.getProduct(productId, context);
      return this._successResponse(product);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleGetProductByBarcode(request, barcode, context) {
    try {
      const product = await this.productService.getProductByBarcode(barcode, context);
      return this._successResponse(product);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleListProducts(request, context) {
    const url = new URL(request.url);
    const filters = {
      page: parseInt(url.searchParams.get('page')) || 1,
      limit: parseInt(url.searchParams.get('limit')) || 50,
      search: url.searchParams.get('search'),
      categoria: url.searchParams.get('categoria'),
      codigo_barras: url.searchParams.get('codigo_barras')
    };

    try {
      const result = await this.productService.listProducts(filters, context);
      return this._successResponse(result);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleUpdateProduct(request, productId, context) {
    let body;
    
    try {
      body = await request.json();
    } catch (error) {
      return this._errorResponse('Invalid JSON in request body', 400);
    }

    try {
      const product = await this.productService.updateProduct(
        productId, 
        body, 
        context
      );
      return this._successResponse(product);
    } catch (error) {
      return this._handleError(error);
    }
  }

  async handleDeleteProduct(request, productId, context) {
    try {
      const result = await this.productService.deleteProduct(productId, context);
      return this._successResponse(result);
    } catch (error) {
      return this._handleError(error);
    }
  }

  _successResponse(data, status = 200) {
    return {
      status,
      data
    };
  }

  _errorResponse(message, status = 400, data = {}) {
    return {
      status,
      data: {
        error: message,
        ...data
      }
    };
  }

  _handleError(error) {
    if (error instanceof ProductError) {
      return this._errorResponse(error.message, error.statusCode);
    }

    console.error('Unexpected error in ProductRoutes:', error);
    return this._errorResponse('Internal server error', 500);
  }
}