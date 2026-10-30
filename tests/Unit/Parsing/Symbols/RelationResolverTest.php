<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\Symbols;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class RelationResolverTest extends TestCase
{
    private const USER = <<<'PHP'
        <?php
        namespace App\Models;

        use Illuminate\Database\Eloquent\Model;
        use Illuminate\Database\Eloquent\Relations\HasMany;
        use Illuminate\Database\Eloquent\Collection;
        use Other\Role;

        /**
         * @property-read Profile $profile
         * @property-read Collection<int, Invoice> $docInvoices
         * @property-read \Vendor\Thing $thing
         * @method Team currentTeam()
         * @method \Vendor\Thing vendorThing()
         * @method Model baseModel()
         */
        class User extends Model
        {
            use HasTeams;

            public function invoices(): HasMany { return $this->hasMany(Invoice::class); }
            public function account() { return $this->hasOne(Account::class, 'owner_id'); }
            public function roles() { return $this->belongsToMany(Role::class)->withTimestamps()->wherePivot('active', 1); }
            public function parent() { return $this->belongsTo(self::class); }
            public function children() { return $this->hasMany(static::class); }
            public function viaThrough() { return $this->hasManyThrough(Invoice::class, Account::class); }
            public function legacy() { return $this->hasMany('App\Models\Invoice'); }
            /** @return HasMany<Order> */
            public function orders() { return $this->ordersQuery(); }
            /** @return HasMany<Order> */
            public function conflicting() { if ($this->x) { return $this->hasMany(Invoice::class); } return $this->hasMany(Account::class); }
            public function branchy() { if ($this->x) { return $this->hasMany(Invoice::class); } return $this->hasMany(Invoice::class); }
            public function closures() { $f = fn () => $this->hasMany(Account::class); return $this->hasMany(Invoice::class); }
            public function notOnThis() { return $other->hasMany(Invoice::class); }
            public function dynamic() { return $this->hasMany($this->related); }
            public function morph() { return $this->morphTo(); }
            public function scalar() { return 1; }
            /** @return \Illuminate\Database\Eloquent\Relations\MorphTo<Model, $this> */
            public function commentable() { return $this->morphTo(); }
            /** @return \Illuminate\Database\Eloquent\Relations\MorphTo<Profile, $this> */
            public function owner() { return $this->morphTo('owner', 'owner_type', 'owner_id'); }
            /** @return Collection<int, Invoice> */
            public function invoiceList() { return $this->invoices()->get(); }
            /** @return HasMany<\Vendor\Thing> */
            public function vendorThings() { return $this->things(); }
            /** @return HasMany<Model> */
            public function anyModel() { return $this->things(); }
        }
        PHP;

    private const FILES = [
        'app/Models/HasTeams.php' => '<?php namespace App\Models; trait HasTeams {
            public function teams() { return $this->belongsToMany(Team::class); }
            public function selfRef() { return $this->belongsTo(self::class); }
            public function staticRef() { return $this->hasMany(static::class); }
            public function parentRef() { return $this->belongsTo(parent::class); }
        }',
        'app/Models/Admin.php' => '<?php namespace App\Models; class Admin extends User {}',
        'app/Models/Profile.php' => '<?php namespace App\Models; class Profile extends \Illuminate\Database\Eloquent\Model {}',
        'app/Models/Order.php' => '<?php namespace App\Models; class Order extends \Illuminate\Database\Eloquent\Model {}',
        'app/Models/Team.php' => '<?php namespace App\Models; class Team extends \Illuminate\Database\Eloquent\Model { use Outer; }',
        'app/Models/SubTeam.php' => '<?php namespace App\Models; class SubTeam extends Team {}',
        'app/Models/Outer.php' => '<?php namespace App\Models; trait Outer { use Inner; }',
        'app/Models/Inner.php' => '<?php namespace App\Models; trait Inner { public function nestedSelfRef() { return $this->belongsTo(self::class); } }',
    ];

    public function testResolvesRelationBodies(): void
    {
        $r = self::resolver();
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\User', 'invoices'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('\App\Models\User', 'INVOICES'));
        self::assertSame('App\Models\Account', $r->relatedClass('App\Models\User', 'account'));
        self::assertSame('Other\Role', $r->relatedClass('App\Models\User', 'roles'));
        self::assertSame('App\Models\User', $r->relatedClass('App\Models\User', 'parent'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\User', 'viaThrough'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\User', 'legacy'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\User', 'branchy'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\User', 'closures'));
        self::assertSame('App\Models\Team', $r->relatedClass('App\Models\User', 'teams'));
    }

    public function testSelfAndStaticFollowTheDeclaringAndCalledClass(): void
    {
        $r = self::resolver();
        self::assertSame('App\Models\User', $r->relatedClass('App\Models\Admin', 'parent'));
        self::assertSame('App\Models\Admin', $r->relatedClass('App\Models\Admin', 'children'));
        self::assertSame('App\Models\Invoice', $r->relatedClass('App\Models\Admin', 'invoices'));
    }

    public function testFallsBackToReturnGenericThenDocTags(): void
    {
        $r = self::resolver();
        self::assertSame('App\Models\Order', $r->relatedClass('App\Models\User', 'orders'));
        self::assertSame('App\Models\Order', $r->relatedClass('App\Models\User', 'conflicting'));
        self::assertSame('App\Models\Profile', $r->relatedClass('App\Models\User', 'profile'));
        self::assertSame('App\Models\Team', $r->relatedClass('App\Models\User', 'currentTeam'));
        self::assertSame('App\Models\Profile', $r->relatedClass('App\Models\Admin', 'profile'));
    }

    public function testUnknownStaysNull(): void
    {
        $r = self::resolver();
        foreach (['notOnThis', 'dynamic', 'morph', 'scalar', 'missing', 'docInvoices', 'thing'] as $relation) {
            self::assertNull($r->relatedClass('App\Models\User', $relation), $relation);
        }
        self::assertNull($r->relatedClass('App\Models\Missing', 'invoices'));
    }

    public function testFollowsRelationChainsHopByHop(): void
    {
        $r = self::resolver();
        self::assertNull($r->followChain('App\Models\User', ['account', 'teams']));
        self::assertSame('App\Models\Team', $r->followChain('App\Models\User', ['parent', 'teams']));
        self::assertSame('App\Models\User', $r->followChain('App\Models\User', []));
        self::assertNull($r->followChain('App\Models\User', ['dynamic', 'teams']));
        self::assertNull($r->followChain('App\Models\User', ['teams', 'missing']));
    }

    public function testMorphToAndNonModelFallbacksAreNull(): void
    {
        $r = self::resolver();
        foreach (['commentable', 'owner', 'invoiceList', 'vendorThings', 'anyModel', 'vendorThing', 'baseModel'] as $relation) {
            self::assertNull($r->relatedClass('App\Models\User', $relation), $relation);
        }
    }

    public function testSelfAndStaticInATraitMeanTheUsingClass(): void
    {
        $r = self::resolver();
        self::assertSame('App\Models\User', $r->relatedClass('App\Models\User', 'selfRef'));
        self::assertSame('App\Models\User', $r->relatedClass('App\Models\Admin', 'selfRef'));
        self::assertSame('App\Models\Team', $r->relatedClass('App\Models\Team', 'nestedSelfRef'));
        self::assertSame('App\Models\Team', $r->relatedClass('App\Models\SubTeam', 'nestedSelfRef'));
        self::assertSame('App\Models\Admin', $r->relatedClass('App\Models\Admin', 'staticRef'));
        self::assertNull($r->relatedClass('App\Models\User', 'parentRef'));
    }

    public function testCachesPerModelAndRelation(): void
    {
        $r = self::resolver();
        self::assertSame($r->relatedClass('App\Models\User', 'account'), $r->relatedClass('App\Models\User', 'account'));
        self::assertSame('App\Models\Admin', $r->relatedClass('App\Models\Admin', 'children'));
        self::assertSame('App\Models\User', $r->relatedClass('App\Models\User', 'children'));
    }

    private static function resolver(): RelationResolver
    {
        $parsed = [(new AstGenerator())->parse(new SourceFile('app/Models/User.php', '/nonexistent/app/Models/User.php', self::USER))];
        foreach (self::FILES as $path => $code) {
            $parsed[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }

        return new RelationResolver((new SymbolTableBuilder())->build(new ParseResult($parsed, [])));
    }
}
