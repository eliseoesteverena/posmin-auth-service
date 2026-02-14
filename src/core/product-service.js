/**
 * Product Service
 * Core business logic for product operations
 */

export class ProductService {
  constructor(dependencies) {
    this.productRepo = dependencies.productRepo;
    this.auditLogRepo = dependencies.auditLogRepo;
  }

  async createProduct(productData, context) {
    const { tenantId, userId } = context;

    // Validaciones
    this._validateProductData(productData);

    // Validar SKU único
    const existingSku = await this.productRepo.checkSkuExists(
      productData.codigo_interno_sku,
      tenantId
    );
    if (existingSku) {
      throw new ProductError('SKU already exists in this tenant', 409);
    }

    // Validar código de barras único (si se proporciona)
    if (productData.codigo_barras) {
      const existingBarcode = await this.productRepo.checkBarcodeExists(
        productData.codigo_barras,
        tenantId
      );
      if (existingBarcode) {
        throw new ProductError('Barcode already exists in this tenant', 409);
      }
    }

    // Crear producto
    const productId = this._generateId();
    const now = new Date().toISOString();

    const newProduct = {
      id: productId,
      tenantId,
      nombre: productData.nombre,
      descripcion: productData.descripcion,
      codigoInternoSku: productData.codigo_interno_sku,
      codigoBarras: productData.codigo_barras,
      stockDisponible: productData.stock_disponible || 0,
      habilitarStock: productData.habilitar_stock || false,
      stockMinimo: productData.stock_minimo || 0,
      precioUnitario: productData.precio_unitario,
      precioCosto: productData.precio_costo,
      categoria: productData.categoria,
      tags: productData.tags,
      isActive: true,
      createdAt: now,
      updatedAt: now,
      createdBy: userId
    };

    await this.productRepo.create(newProduct);

    // Audit log
    await this._logEvent(userId, tenantId, 'product_created', 'product', productId, {
      nombre: newProduct.nombre,
      codigo_barras: newProduct.codigoBarras,
      precio_unitario: newProduct.precioUnitario
    });

    return this._formatProduct(newProduct);
  }

  async getProduct(productId, context) {
    const { tenantId } = context;

    const product = await this.productRepo.findById(productId, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    return this._formatProduct(product);
  }

  async getProductByBarcode(barcode, context) {
    const { tenantId } = context;

    const product = await this.productRepo.findByBarcode(barcode, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    return this._formatProduct(product);
  }

  async listProducts(filters, context) {
    const { tenantId } = context;

    const result = await this.productRepo.findAll(filters, tenantId);

    return {
      data: result.data.map(p => this._formatProduct(p)),
      pagination: result.pagination
    };
  }

  async updateProduct(productId, updates, context) {
    const { tenantId, userId } = context;

    // Obtener producto actual
    const product = await this.productRepo.findById(productId, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    // Validar datos si hay cambios
    if (updates.precio_unitario !== undefined && updates.precio_unitario <= 0) {
      throw new ProductError('Price must be greater than 0', 400);
    }

    // Validar SKU único si cambió
    if (updates.codigo_interno_sku && updates.codigo_interno_sku !== product.codigo_interno_sku) {
      const exists = await this.productRepo.checkSkuExists(
        updates.codigo_interno_sku,
        tenantId,
        productId
      );
      if (exists) {
        throw new ProductError('SKU already exists in this tenant', 409);
      }
    }

    // Validar código de barras único si cambió
    if (updates.codigo_barras && updates.codigo_barras !== product.codigo_barras) {
      if (!this._isValidBarcode(updates.codigo_barras)) {
        throw new ProductError('Invalid barcode format', 400);
      }

      const exists = await this.productRepo.checkBarcodeExists(
        updates.codigo_barras,
        tenantId,
        productId
      );
      if (exists) {
        throw new ProductError('Barcode already exists in this tenant', 409);
      }
    }

    // Mapear campos
    const mappedUpdates = {};
    if (updates.nombre !== undefined) mappedUpdates.nombre = updates.nombre;
    if (updates.descripcion !== undefined) mappedUpdates.descripcion = updates.descripcion;
    if (updates.codigo_barras !== undefined) mappedUpdates.codigoBarras = updates.codigo_barras;
    if (updates.precio_unitario !== undefined) mappedUpdates.precioUnitario = updates.precio_unitario;
    if (updates.precio_costo !== undefined) mappedUpdates.precioCosto = updates.precio_costo;
    if (updates.stock_disponible !== undefined) mappedUpdates.stockDisponible = updates.stock_disponible;
    if (updates.stock_minimo !== undefined) mappedUpdates.stockMinimo = updates.stock_minimo;
    if (updates.habilitar_stock !== undefined) mappedUpdates.habilitarStock = updates.habilitar_stock;
    if (updates.categoria !== undefined) mappedUpdates.categoria = updates.categoria;
    if (updates.tags !== undefined) mappedUpdates.tags = updates.tags;

    // Actualizar
    await this.productRepo.update(productId, mappedUpdates, tenantId);

    // Audit log
    await this._logEvent(userId, tenantId, 'product_updated', 'product', productId, {
      updates: mappedUpdates
    });

    // Retornar producto actualizado
    const updated = await this.productRepo.findById(productId, tenantId);
    return this._formatProduct(updated);
  }

  async deleteProduct(productId, context) {
    const { tenantId, userId } = context;

    // Verificar que existe
    const product = await this.productRepo.findById(productId, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    // Soft delete
    await this.productRepo.delete(productId, tenantId);

    // Audit log
    await this._logEvent(userId, tenantId, 'product_deleted', 'product', productId, {
      nombre: product.nombre
    });

    return { message: 'Product deleted successfully' };
  }

  _validateProductData(data) {
    if (!data.nombre || data.nombre.trim().length === 0) {
      throw new ProductError('Product name is required', 400);
    }
    if (!data.codigo_interno_sku || data.codigo_interno_sku.trim().length === 0) {
      throw new ProductError('SKU is required', 400);
    }
    if (!data.precio_unitario || data.precio_unitario <= 0) {
      throw new ProductError('Price must be greater than 0', 400);
    }

    // Validar formato de código de barras si se proporciona
    if (data.codigo_barras && !this._isValidBarcode(data.codigo_barras)) {
      throw new ProductError(
        'Invalid barcode format. Must be EAN-13 (13 digits), UPC (12 digits), or EAN-8 (8 digits)', 
        400
      );
    }
  }

  _isValidBarcode(barcode) {
    // EAN-13: 13 dígitos
    // UPC-A: 12 dígitos
    // EAN-8: 8 dígitos
    const cleaned = barcode.replace(/[^0-9]/g, '');
    return /^[0-9]{8}$|^[0-9]{12,13}$/.test(cleaned);
  }

  _formatProduct(product) {
    if (!product) return null;

    return {
      id: product.id,
      tenant_id: product.tenant_id,
      nombre: product.nombre,
      descripcion: product.descripcion,
      codigo_interno_sku: product.codigo_interno_sku,
      codigo_barras: product.codigo_barras,
      stock_disponible: product.stock_disponible,
      habilitar_stock: !!product.habilitar_stock,
      stock_minimo: product.stock_minimo,
      precio_unitario: product.precio_unitario,
      precio_costo: product.precio_costo,
      categoria: product.categoria,
      tags: product.tags,
      is_active: !!product.is_active,
      created_at: product.created_at,
      updated_at: product.updated_at,
      created_by: product.created_by
    };
  }

  async _logEvent(userId, tenantId, event, entityType, entityId, metadata) {
    try {
      await this.auditLogRepo.log({
        id: this._generateId(),
        userId,
        tenantId,
        event,
        entityType,
        entityId,
        metadata: JSON.stringify(metadata),
        createdAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error logging event:', error);
      // No lanzar error, logging no debe romper el flujo
    }
  }

  _generateId() {
    return `prod-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }
}

export class ProductError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = 'ProductError';
    this.statusCode = statusCode;
  }
}