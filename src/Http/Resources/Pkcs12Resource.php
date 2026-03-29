<?php

declare(strict_types=1);

namespace CA\Pkcs12\Http\Resources;

use CA\Pkcs12\Models\Pkcs12Bundle;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin Pkcs12Bundle
 */
class Pkcs12Resource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'uuid' => $this->uuid,
            'certificate_id' => $this->certificate_id,
            'friendly_name' => $this->friendly_name,
            'include_chain' => $this->include_chain,
            'encryption_algorithm' => $this->encryption_algorithm,
            'mac_algorithm' => $this->mac_algorithm,
            'created_at' => $this->created_at?->toIso8601String(),
            'updated_at' => $this->updated_at?->toIso8601String(),
        ];
    }
}
