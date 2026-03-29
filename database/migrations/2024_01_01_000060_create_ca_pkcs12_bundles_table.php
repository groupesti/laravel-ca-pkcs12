<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ca_pkcs12_bundles', function (Blueprint $table): void {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->foreignId('certificate_id')
                ->constrained('ca_certificates')
                ->cascadeOnDelete();
            $table->string('tenant_id')->nullable()->index();
            $table->string('friendly_name')->nullable();
            $table->boolean('include_chain')->default(true);
            $table->string('encryption_algorithm')->default('aes-256-cbc');
            $table->string('mac_algorithm')->default('sha256');
            $table->string('storage_path')->nullable();
            $table->timestamps();

            $table->index(['tenant_id', 'certificate_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ca_pkcs12_bundles');
    }
};
