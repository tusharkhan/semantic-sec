<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\Symbols;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class SymbolTableTest extends TestCase
{
    public function testIsSubclassOfFollowsParentsAndInterfaceExtends(): void
    {
        $table = self::table([
            'app/Contracts.php' => '<?php namespace App;
                interface Base {}
                interface Middle extends Base, \Countable {}
                interface Leaf extends Middle {}',
            'app/Impl.php' => '<?php namespace App; class Impl implements Leaf {}',
            'app/Child.php' => '<?php namespace App; class Child extends Impl {}',
            'app/Model.php' => '<?php namespace App; class Model extends \Illuminate\Database\Eloquent\Model {}',
            'app/Cycle.php' => '<?php namespace App; class A extends B {} class B extends A {} interface I extends J {} interface J extends I {}',
        ]);

        self::assertTrue($table->isSubclassOf('App\Child', 'App\Impl'));
        self::assertTrue($table->isSubclassOf('App\Child', 'App\Base'));
        self::assertTrue($table->isSubclassOf('App\Child', 'Countable'));
        self::assertTrue($table->isSubclassOf('App\Leaf', 'App\Base'));
        self::assertTrue($table->isSubclassOf('\App\Model', '\Illuminate\Database\Eloquent\Model'));
        self::assertFalse($table->isSubclassOf('App\Impl', 'App\Child'));
        self::assertFalse($table->isSubclassOf('App\Impl', 'App\Impl'));
        self::assertFalse($table->isSubclassOf('App\Missing', 'App\Base'));
        self::assertTrue($table->isSubclassOf('App\A', 'App\B'));
        self::assertFalse($table->isSubclassOf('App\A', 'App\Other'));
        self::assertFalse($table->isSubclassOf('App\I', 'App\Other'));
    }

    public function testImplementationsListsConcreteClassesTransitively(): void
    {
        $table = self::table([
            'app/Contracts.php' => '<?php namespace App; interface Repo {} interface UserRepo extends Repo {}',
            'app/Classes.php' => '<?php namespace App;
                class Eloquent implements UserRepo {}
                class Cached extends Eloquent {}
                abstract class AbstractRepo implements Repo {}
                class Concrete extends AbstractRepo {}
                enum Kind: string implements Repo { case A = "a"; }
                class Unrelated {}
                trait T {}',
        ]);

        self::assertSame(['App\Eloquent', 'App\Cached', 'App\Concrete', 'App\Kind'], $table->implementations('App\Repo'));
        self::assertSame(['App\Eloquent', 'App\Cached'], $table->implementations('\App\UserRepo'));
        self::assertSame([], $table->implementations('App\Nothing'));
    }

    public function testFindPropertyWalksOwnTraitsThenParents(): void
    {
        $table = self::table([
            'app/T.php' => '<?php namespace App; trait T { protected Svc $fromTrait; protected Svc $shadow; }',
            'app/Base.php' => '<?php namespace App; class Base { protected Svc $fromParent; protected Svc $own; protected Other $shadow; }',
            'app/Child.php' => '<?php namespace App; class Child extends Base { use T; protected Other $own; public function __construct(private Svc $promoted) {} }',
        ]);

        self::assertSame('App\Svc', $table->findProperty('App\Child', 'fromTrait')?->type);
        self::assertSame('App\Svc', $table->findProperty('App\Child', 'fromParent')?->type);
        self::assertSame('App\Other', $table->findProperty('App\Child', 'own')?->type);
        self::assertSame('App\Svc', $table->findProperty('App\Child', 'shadow')?->type);
        self::assertSame('App\Svc', $table->findProperty('\App\Child', 'promoted')?->type);
        self::assertNull($table->findProperty('App\Child', 'nope'));
        self::assertNull($table->findProperty('App\Missing', 'own'));
    }

    /** @param array<string, string> $files */
    private static function table(array $files): SymbolTable
    {
        $parsed = [];
        foreach ($files as $path => $code) {
            $parsed[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }

        return (new SymbolTableBuilder())->build(new ParseResult($parsed, []));
    }
}
