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
    const existingSku = await this.productRepo.findBySku(
      productData.codigo_interno_sku,
      tenantId
    );
    if (existingSku) {
      throw new ProductError('SKU already exists in this tenant', 409);
    }

    // ✅ NUEVO: Validar código de barras único
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
      codigoBarras: productData.codigo_barras,  // ✅ NUEVO
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
    await this.auditLogRepo.log({
      id: this._generateId(),
      userId,
      tenantId,
      event: 'product_created',
      entityType: 'product',
      entityId: productId,
      metadata: JSON.stringify({
        nombre: newProduct.nombre,
        codigo_barras: newProduct.codigoBarras  // ✅ NUEVO
      }),
      createdAt: now
    });

    return this._formatProduct(newProduct);
  }

  async updateProduct(productId, updates, context) {
    const { tenantId, userId } = context;

    // Obtener producto actual
    const product = await this.productRepo.findById(productId, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    // ✅ NUEVO: Si se actualiza código de barras, validar unicidad
    if (updates.codigo_barras && updates.codigo_barras !== product.codigo_barras) {
      const exists = await this.productRepo.checkBarcodeExists(
        updates.codigo_barras,
        tenantId,
        productId  // Excluir producto actual
      );
      if (exists) {
        throw new ProductError('Barcode already exists in this tenant', 409);
      }
    }

    // Actualizar
    await this.productRepo.update(productId, updates, tenantId);

    // Audit log
    await this.auditLogRepo.log({
      id: this._generateId(),
      userId,
      tenantId,
      event: 'product_updated',
      entityType: 'product',
      entityId: productId,
      metadata: JSON.stringify({
        updates,
        old_barcode: product.codigo_barras,  // ✅ NUEVO
        new_barcode: updates.codigo_barras
      }),
      createdAt: new Date().toISOString()
    });

    return await this.productRepo.findById(productId, tenantId);
  }

  // ✅ NUEVO: Buscar por código de barras
  async getProductByBarcode(barcode, context) {
    const { tenantId } = context;

    const product = await this.productRepo.findByBarcode(barcode, tenantId);
    if (!product) {
      throw new ProductError('Product not found', 404);
    }

    return this._formatProduct(product);
  }

  _validateProductData(data) {
    if (!data.nombre || data.nombre.trim().length === 0) {
      throw new ProductError('Product name is required', 400);
    }
    if (!data.codigo_interno_sku) {
      throw new ProductError('SKU is required', 400);
    }
    if (!data.precio_unitario || data.precio_unitario <= 0) {
      throw new ProductError('Price must be greater than 0', 400);
    }

    // ✅ NUEVO: Validar formato de código de barras
    if (data.codigo_barras) {
      if (!this._isValidBarcode(data.codigo_barras)) {
        throw new ProductError(
          'Invalid barcode format. Must be EAN-13 (13 digits) or UPC (12 digits)', 
          400
        );
      }
    }
  }

  // ✅ NUEVO: Validar formato de código de barras
  _isValidBarcode(barcode) {
    // EAN-13: 13 dígitos
    // UPC-A: 12 dígitos
    // EAN-8: 8 dígitos
    const cleaned = barcode.replace(/[^0-9]/g, '');
    return /^[0-9]{8}$|^[0-9]{12,13}$/.test(cleaned);
  }

  _formatProduct(product) {
    return {
      id: product.id,
      tenant_id: product.tenant_id,
      nombre: product.nombre,
      descripcion: product.descripcion,
      codigo_interno_sku: product.codigo_interno_sku,
      codigo_barras: product.codigo_barras,  // ✅ INCLUIDO
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