<?php

namespace App\Http\Requests\Safe;

use Illuminate\Foundation\Http\FormRequest;

class UpdateListingRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('listing')->user_id === $this->user()->id;
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'title' => ['sometimes', 'string', 'max:120'],
            'price' => ['sometimes', 'numeric', 'min:0'],
        ];
    }
}
