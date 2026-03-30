<?php

declare(strict_types=1);

namespace CA\Pkcs12\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CreatePkcs12Request extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            'certificate_id' => ['required', 'exists:ca_certificates,id'],
            'password' => ['required', 'string', 'min:8'],
            'friendly_name' => ['sometimes', 'nullable', 'string', 'max:255'],
            'include_chain' => ['sometimes', 'boolean'],
            'encryption_algorithm' => ['sometimes', 'string', 'in:aes-256-cbc,aes-128-cbc,3des-cbc'],
            'legacy' => ['sometimes', 'boolean'],
        ];
    }
}
