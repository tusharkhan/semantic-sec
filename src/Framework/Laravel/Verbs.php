<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

/** The one list of Eloquent / query-builder read, write and lookup verbs (lower-cased), shared by the map and the selector. */
final class Verbs
{
    // Calls that read rows out of a query.
    public const READS = ['find', 'findorfail', 'findmany', 'first', 'firstorfail', 'firstwhere', 'sole', 'get', 'paginate', 'simplepaginate', 'cursorpaginate', 'cursor', 'exists', 'doesntexist', 'count', 'pluck', 'value'];

    // Calls that change rows; every insert* and update* call is one too (see isWrite()).
    public const WRITES = [
        'create', 'createmany', 'createquietly', 'forcecreate', 'save', 'savequietly', 'savemany', 'push',
        'update', 'updatequietly', 'updateorcreate', 'updateorinsert', 'updateexistingpivot', 'firstorcreate', 'firstornew',
        'delete', 'deletequietly', 'forcedelete', 'destroy', 'restore', 'truncate', 'insert', 'insertorignore', 'insertgetid', 'upsert',
        'attach', 'sync', 'syncwithoutdetaching', 'detach', 'toggle', 'associate', 'dissociate',
        'increment', 'decrement', 'incrementeach', 'decrementeach', 'touch',
    ];

    // Pivot and relation writes: with a non-constant argument they choose which rows get linked.
    public const RELATION_WRITES = ['sync', 'syncwithoutdetaching', 'attach', 'detach', 'toggle', 'updateexistingpivot', 'associate', 'dissociate', 'savemany', 'createmany'];

    // Statement-level writes on the DB facade itself (DB::delete(...)).
    public const DB_WRITES = ['insert', 'update', 'delete', 'statement', 'unprepared', 'affectingstatement'];

    // Calls that leave the user's relation scope.
    public const SCOPE_RESETS = ['newquery', 'query', 'newmodelquery', 'replicate', 'getmodel', 'getrelated', 'newmodelinstance', 'make'];

    public static function isWrite(string $name): bool
    {
        return in_array($name, self::WRITES, true) || str_starts_with($name, 'insert') || str_starts_with($name, 'update');
    }

    // A call that finds rows by a value: find*, where*, first*, sole, or destroy (which looks up by key before deleting).
    public static function isLookup(string $name): bool
    {
        return str_starts_with($name, 'find') || str_starts_with($name, 'where') || str_starts_with($name, 'first') || $name === 'sole' || $name === 'destroy';
    }
}
