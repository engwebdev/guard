<?php

namespace App\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

class Token extends Model
{
    protected $table = 'tokens';

    protected $casts = [
        'abilities' => 'array',
        'revoked' => 'bool',
        'last_used_at' => 'datetime',
        'date_time_expires_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    protected $fillable = [
        'id',
        'guardable',
        'namespaceable',
        'name',
        'tokenable',
//        'token',
        'scopes',
        'abilities',
        'revoked',
        'last_used_at',
        'date_time_expires_at',
        'expires_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'token',
    ];

    /**
     * Get the tokenable model that the access token belongs to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function tokenable()
    {
        return $this->morphTo('tokenable');
    }

    /**
     * Find the token instance matching the given token.
     *
     * @param string $token
     * @return static|null
     */
    public static function findToken($token)
    {
//        return static::where('token', hash('sha256', $token))->first();
//
//        if ($instance = static::find($id)) {
//            return hash_equals($instance->token, hash('sha256', $token)) ? $instance : null;
//        }
    }
    /**
     * Determine if the token has a given ability.
     *
     * @param  string  $ability
     * @return bool
     */
    public function can($ability)
    {
        // $this->abilities // todo
//        return in_array('*', $this->abilities) ||
//            array_key_exists($ability, array_flip($this->abilities));
    }

    /**
     * Determine if the token is missing a given ability.
     *
     * @param  string  $ability
     * @return bool
     */
    public function cant($ability)
    {
        return ! $this->can($ability);
    }


    public function user()
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}

// php artisan make:migration create_tokens_table
/*



*/
