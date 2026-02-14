/**
 * Product Repository
 * Handles all product-related database operations
 */

export class ProductRepository {
  constructor(db) {
    this.db = db;
  }

  async create(productData) {
    const query = `
      INSERT INTO productos (
        id, tenant_id, nombre, descripcion, codigo_interno_sku,
        codigo_barras, stock_disponible, habilitar_stock, stock_minimo,
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
        productData.descripcion || null,
        productData.codigoInternoSku,
        productData.codigoBarras || null,
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
        productData.createdBy || null
      )
      .run();
  }

  async findById(id, tenantId) {
    return await this.db
      .prepare(`
        SELECT * FROM productos 
        WHERE id = ? AND tenant_id = ? AND is_active = 1
      `)
      .bind(id, tenantId)
      .first();
  }

  async findByBarcode(barcode, tenantId) {
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
    const { page = 1, limit = 50, search, categoria, codigo_barras } = filters;
    const offset = (page - 1) * limit;

    let whereClauses = ['tenant_id = ?', 'is_active = 1'];
    let values = [tenantId];

    if (search) {
      whereClauses.push(`(
        nombre LIKE ? OR 
        codigo_interno_sku LIKE ? OR 
        codigo_barras LIKE ? OR
        descripcion LIKE ?
      )`);
      const searchPattern = `%${search}%`;
      values.push(searchPattern, searchPattern, searchPattern, searchPattern);
    }

    if (categoria) {
      whereClauses.push('categoria = ?');
      values.push(categoria);
    }

    if (codigo_barras) {
      whereClauses.push('codigo_barras = ?');
      values.push(codigo_barras);
    }

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
        total: countResult?.total || 0,
        totalPages: Math.ceil((countResult?.total || 0) / limit)
      }
    };
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
    if (updates.codigoBarras !== undefined) {
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
    if (updates.stockMinimo !== undefined) {
      setClauses.push('stock_minimo = ?');
      values.push(updates.stockMinimo);
    }
    if (updates.habilitarStock !== undefined) {
      setClauses.push('habilitar_stock = ?');
      values.push(updates.habilitarStock ? 1 : 0);
    }
    if (updates.categoria !== undefined) {
      setClauses.push('categoria = ?');
      values.push(updates.categoria);
    }
    if (updates.tags !== undefined) {
      setClauses.push('tags = ?');
      values.push(updates.tags);
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

  async delete(productId, tenantId) {
    // Soft delete
    return await this.db
      .prepare(`
        UPDATE productos 
        SET is_active = 0, updated_at = ?
        WHERE id = ? AND tenant_id = ?
      `)
      .bind(new Date().toISOString(), productId, tenantId)
      .run();
  }

  async checkBarcodeExists(barcode, tenantId, excludeProductId = null) {
    if (!barcode) return false;

    let query = `
      SELECT id FROM productos 
      WHERE tenant_id = ? AND codigo_barras = ? AND is_active = 1
    `;
    let values = [tenantId, barcode];

    if (excludeProductId) {
      query += ' AND id != ?';
      values.push(excludeProductId);
    }

    const result = await this.db.prepare(query).bind(...values).first();
    return !!result;
  }

  async checkSkuExists(sku, tenantId, excludeProductId = null) {
    let query = `
      SELECT id FROM productos 
      WHERE tenant_id = ? AND codigo_interno_sku = ? AND is_active = 1
    `;
    let values = [tenantId, sku];

    if (excludeProductId) {
      query += ' AND id != ?';
      values.push(excludeProductId);
    }

    const result = await this.db.prepare(query).bind(...values).first();
    return !!result;
  }
}