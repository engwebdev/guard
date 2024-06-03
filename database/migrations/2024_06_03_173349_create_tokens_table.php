<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('tokens', function (Blueprint $table) {
            $table->string('id', 100)->primary();
            $table->string('guardable_type')->nullable();
            $table->unsignedBigInteger('guardable_id')->nullable();
            $table->string('namespaceable_type')->nullable();
            $table->unsignedBigInteger('namespaceable_id')->nullable();
            $table->string('name')->nullable();
            $table->string('tokenable_type')->nullable();
            $table->unsignedBigInteger('tokenable_id')->nullable();
            $table->text('token')->unique();
            $table->text('scopes')->nullable();
            $table->text('abilities')->nullable();
            $table->boolean('revoked');
            $table->timestamp('last_used_at')->nullable();
            $table->dateTime('date_time_expires_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('tokens');
    }
};
