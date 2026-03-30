<?php

declare(strict_types=1);

namespace CA\Pkcs12\Models;

use CA\Crt\Models\Certificate;
use CA\Key\Models\Key;
use CA\Traits\Auditable;
use CA\Traits\BelongsToTenant;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOneThrough;

class Pkcs12Bundle extends Model
{
    use HasUuids;
    use Auditable;
    use BelongsToTenant;

    protected $table = 'ca_pkcs12_bundles';

    protected $fillable = [
        'uuid',
        'certificate_id',
        'tenant_id',
        'friendly_name',
        'include_chain',
        'encryption_algorithm',
        'mac_algorithm',
        'storage_path',
    ];

    protected function casts(): array
    {
        return [
            'include_chain' => 'boolean',
        ];
    }

    /**
     * @return array<int, string>
     */
    public function uniqueIds(): array
    {
        return ['uuid'];
    }

    // ---- Relationships ----

    public function certificate(): BelongsTo
    {
        return $this->belongsTo(Certificate::class, 'certificate_id');
    }

    /**
     * Access the key through the certificate relationship.
     */
    public function key(): HasOneThrough
    {
        return $this->hasOneThrough(
            Key::class,
            Certificate::class,
            'id',               // Foreign key on ca_certificates
            'id',               // Foreign key on ca_keys
            'certificate_id',   // Local key on ca_pkcs12_bundles
            'key_id',           // Local key on ca_certificates
        );
    }
}
