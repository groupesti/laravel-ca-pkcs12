<?php

declare(strict_types=1);

namespace CA\Pkcs12\Http\Controllers;

use CA\Crt\Models\Certificate;
use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use CA\Pkcs12\Http\Requests\CreatePkcs12Request;
use CA\Pkcs12\Http\Resources\Pkcs12Resource;
use CA\Pkcs12\Models\Pkcs12Bundle;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;

class Pkcs12Controller extends Controller
{
    public function __construct(
        private readonly Pkcs12ManagerInterface $manager,
    ) {}

    /**
     * Create a new PKCS#12 bundle.
     */
    public function create(CreatePkcs12Request $request): JsonResponse
    {
        $cert = Certificate::findOrFail($request->validated('certificate_id'));
        $key = $cert->key;

        if ($key === null) {
            return response()->json([
                'error' => 'No private key associated with this certificate.',
            ], 422);
        }

        $bundle = $this->manager->create(
            cert: $cert,
            key: $key,
            password: $request->validated('password'),
            friendlyName: $request->validated('friendly_name'),
        );

        return response()->json(
            new Pkcs12Resource($bundle),
            201,
        );
    }

    /**
     * Show PKCS#12 bundle metadata.
     */
    public function show(string $uuid): JsonResponse
    {
        $bundle = $this->manager->findByUuid($uuid);

        if ($bundle === null) {
            return response()->json(['error' => 'PKCS#12 bundle not found.'], 404);
        }

        return response()->json(new Pkcs12Resource($bundle));
    }

    /**
     * Export PKCS#12 bundle as binary download.
     */
    public function export(Request $request, string $uuid): Response|JsonResponse
    {
        $request->validate([
            'password' => ['required', 'string', 'min:8'],
        ]);

        $bundle = $this->manager->findByUuid($uuid);

        if ($bundle === null) {
            return response()->json(['error' => 'PKCS#12 bundle not found.'], 404);
        }

        $der = $this->manager->export($bundle, $request->input('password'));

        $filename = ($bundle->friendly_name ?? $bundle->uuid) . '.p12';

        return response($der, 200, [
            'Content-Type' => 'application/x-pkcs12',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
            'Content-Length' => strlen($der),
        ]);
    }

    /**
     * Import a PKCS#12 file (parse and display contents).
     */
    public function import(Request $request): JsonResponse
    {
        $request->validate([
            'file' => ['required', 'file'],
            'password' => ['required', 'string'],
        ]);

        $file = $request->file('file');
        $pkcs12Data = file_get_contents($file->getRealPath());
        $password = $request->input('password');

        try {
            $result = $this->manager->parse($pkcs12Data, $password);
        } catch (\RuntimeException $e) {
            return response()->json([
                'error' => 'Failed to parse PKCS#12 file.',
                'message' => $e->getMessage(),
            ], 422);
        }

        return response()->json([
            'data' => [
                'has_private_key' => !empty($result['privateKey']),
                'has_certificate' => !empty($result['certificate']),
                'chain_count' => count($result['chain']),
                'certificate' => $result['certificate'],
                'chain' => $result['chain'],
            ],
        ]);
    }
}
