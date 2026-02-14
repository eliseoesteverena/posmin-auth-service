export class ProductRepository {
  constructor(db) {
    this.db = db;
  }

  async create(productData) {
    const query = `
      INSERT INTO productos (
        id, tenant_id, nombre, descripcion, codigo_interno_sku,
        codigo_barras,  -- ✅ NUEVO
        stock_disponible, habilitar_stock, stock_minimo,
        precio_unitario, precio_costo, categoria, tags,
        is_active, created_at, updated_at, created_by
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    return await this.db
      .prepare(query)
      .bind(
        productData.id,
        productData.tenantId,
        productData.nombre,
        productData.descripcion,
        productData.codigoInternoSku,
        productData.codigoBarras || null,  // ✅ NUEVO
        productData.stockDisponible || 0,
        productData.habilitarStock ? 1 : 0,
        productData.stockMinimo || 0,
        productData.precioUnitario,
        productData.precioCosto || null,
        productData.categoria || null,
        productData.tags || null,
        productData.isActive ? 1 : 0,
        productData.createdAt,
        productData.updatedAt,
        productData.createdBy
      )
      .run();
  }

  async update(productId, updates, tenantId) {
    const setClauses = [];
    const values = [];

    if (updates.nombre !== undefined) {
      setClauses.push('nombre = ?');
      values.push(updates.nombre);
    }
    if (updates.descripcion !== undefined) {
      setClauses.push('descripcion = ?');
      values.push(updates.descripcion);
    }
    if (updates.codigoBarras !== undefined) {  // ✅ NUEVO
      setClauses.push('codigo_barras = ?');
      values.push(updates.codigoBarras);
    }
    if (updates.precioUnitario !== undefined) {
      setClauses.push('precio_unitario = ?');
      values.push(updates.precioUnitario);
    }
    if (updates.precioCosto !== undefined) {
      setClauses.push('precio_costo = ?');
      values.push(updates.precioCosto);
    }
    if (updates.stockDisponible !== undefined) {
      setClauses.push('stock_disponible = ?');
      values.push(updates.stockDisponible);
    }
    if (updates.categoria !== undefined) {
      setClauses.push('categoria = ?');
      values.push(updates.categoria);
    }

    setClauses.push('updated_at = ?');
    values.push(new Date().toISOString());

    values.push(productId, tenantId);

    const query = `
      UPDATE productos 
      SET ${setClauses.join(', ')}
      WHERE id = ? AND tenant_id = ?
    `;

    return await this.db.prepare(query).bind(...values).run();
  }

  async findByBarcode(barcode, tenantId) {  // ✅ NUEVO
    return await this.db
      .prepare(`
        SELECT * FROM productos 
        WHERE tenant_id = ? 
          AND codigo_barras = ? 
          AND is_active = 1
      `)
      .bind(tenantId, barcode)
      .first();
  }

  async findBySku(sku, tenantId) {
    return await this.db
      .prepare(`
        SELECT * FROM productos 
        WHERE tenant_id = ? 
          AND codigo_interno_sku = ? 
          AND is_active = 1
      `)
      .bind(tenantId, sku)
      .first();
  }

  async findAll(filters, tenantId) {
    const { page = 1, limit = 50, search, categoria, codigo_barras } = filters;  // ✅ NUEVO
    const offset = (page - 1) * limit;

    let whereClauses = ['tenant_id = ?'];
    let values = [tenantId];

    if (search) {
      whereClauses.push(`(
        nombre LIKE ? OR 
        codigo_interno_sku LIKE ? OR 
        codigo_barras LIKE ? OR  -- ✅ NUEVO
        descripcion LIKE ?
      )`);
      const searchPattern = `%${search}%`;
      values.push(searchPattern, searchPattern, searchPattern, searchPattern);
    }

    if (categoria) {
      whereClauses.push('categoria = ?');
      values.push(categoria);
    }

    if (codigo_barras) {  // ✅ NUEVO - Filtro específico
      whereClauses.push('codigo_barras = ?');
      values.push(codigo_barras);
    }

    whereClauses.push('is_active = 1');

    const query = `
      SELECT * FROM productos
      WHERE ${whereClauses.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `;

    const results = await this.db
      .prepare(query)
      .bind(...values, limit, offset)
      .all();

    // Count total
    const countQuery = `
      SELECT COUNT(*) as total FROM productos
      WHERE ${whereClauses.join(' AND ')}
    `;

    const countResult = await this.db
      .prepare(countQuery)
      .bind(...values)
      .first();

    return {
      data: results.results || [],
      pagination: {
        page,
        limit,
        total: countResult.total,
        totalPages: Math.ceil(countResult.total / limit)
      }
    };
  }

  async checkBarcodeExists(barcode, tenantId, excludeProductId = null) {  // ✅ NUEVO
    if (!barcode) return false;

    let query = `
      SELECT id FROM productos 
      WHERE tenant_id = ? AND codigo_barras = ?
    `;
    let values = [tenantId, barcode];

    if (excludeProductId) {
      query += ' AND id != ?';
      values.push(excludeProductId);
    }

    const result = await this.db.prepare(query).bind(...values).first();
    return !!result;
  }
}